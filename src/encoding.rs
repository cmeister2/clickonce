//! Strict decoding of the Unicode encodings required by XML.

use std::borrow::Cow;

use crate::Error;

/// The encoding identified from a byte-order mark or XML byte signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TextEncoding {
    /// UTF-8, with or without its optional byte-order mark.
    Utf8,
    /// UTF-16 with the least significant byte first.
    Utf16Le,
    /// UTF-16 with the most significant byte first.
    Utf16Be,
}

/// Decodes XML bytes without substituting replacement characters for errors.
///
/// XML declarations are checked against the detected byte encoding. This check
/// belongs to the byte-oriented API: a caller supplying an already decoded
/// `&str` may retain the declaration from the original UTF-16 document.
///
/// # Errors
///
/// Returns [`Error::Encoding`] for malformed Unicode, unsupported encodings, or
/// an XML declaration that conflicts with the actual byte encoding.
pub(crate) fn decode(input: &[u8]) -> Result<Cow<'_, str>, Error> {
    if is_utf32(input) {
        return Err(Error::Encoding("UTF-32 is not supported".into()));
    }

    let (encoding, bytes) = if let Some(bytes) = input.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        (TextEncoding::Utf8, bytes)
    } else if let Some(bytes) = input.strip_prefix(&[0xff, 0xfe]) {
        (TextEncoding::Utf16Le, bytes)
    } else if let Some(bytes) = input.strip_prefix(&[0xfe, 0xff]) {
        (TextEncoding::Utf16Be, bytes)
    } else if input.starts_with(&[b'<', 0, b'?', 0]) {
        (TextEncoding::Utf16Le, input)
    } else if input.starts_with(&[0, b'<', 0, b'?']) {
        (TextEncoding::Utf16Be, input)
    } else {
        (TextEncoding::Utf8, input)
    };

    let text = match encoding {
        TextEncoding::Utf8 => Cow::Borrowed(
            std::str::from_utf8(bytes)
                .map_err(|error| Error::Encoding(format!("invalid UTF-8: {error}")))?,
        ),
        TextEncoding::Utf16Le | TextEncoding::Utf16Be => {
            let chunks = bytes.chunks_exact(2);
            if !chunks.remainder().is_empty() {
                return Err(Error::Encoding("UTF-16 has an incomplete code unit".into()));
            }
            let units: Vec<_> = chunks
                .map(|pair| {
                    if encoding == TextEncoding::Utf16Le {
                        u16::from_le_bytes([pair[0], pair[1]])
                    } else {
                        u16::from_be_bytes([pair[0], pair[1]])
                    }
                })
                .collect();
            Cow::Owned(
                String::from_utf16(&units)
                    .map_err(|error| Error::Encoding(format!("invalid UTF-16: {error}")))?,
            )
        }
    };
    validate_declaration(&text, encoding)?;
    Ok(text)
}

/// Detects the four UTF-32 byte orders before UTF-16 BOM detection can match.
fn is_utf32(input: &[u8]) -> bool {
    /// UTF-32 byte-order marks and initial less-than characters in all byte orders.
    const SIGNATURES: [[u8; 4]; 8] = [
        [0, 0, 0xfe, 0xff],
        [0xff, 0xfe, 0, 0],
        [0, 0, 0xff, 0xfe],
        [0xfe, 0xff, 0, 0],
        [0, 0, 0, b'<'],
        [b'<', 0, 0, 0],
        [0, 0, b'<', 0],
        [0, b'<', 0, 0],
    ];
    SIGNATURES
        .iter()
        .any(|signature| input.starts_with(signature))
}

/// Checks a well-formed encoding attribute in the initial XML declaration.
///
/// The XML parser reports malformed declaration syntax. Walking attribute
/// values here avoids mistaking text within another attribute for `encoding`.
///
/// # Errors
///
/// Returns [`Error::Encoding`] if the declared encoding is unsupported or
/// disagrees with the byte encoding.
fn validate_declaration(text: &str, encoding: TextEncoding) -> Result<(), Error> {
    let Some(rest) = text.strip_prefix("<?xml") else {
        return Ok(());
    };
    if !rest.starts_with(is_xml_space) {
        return Ok(());
    }
    let Some(end) = rest.find("?>") else {
        return Ok(());
    };
    let mut attributes = &rest[..end];
    loop {
        attributes = attributes.trim_start_matches(is_xml_space);
        if attributes.is_empty() {
            return Ok(());
        }
        let name_end = attributes
            .find(|character: char| is_xml_space(character) || character == '=')
            .unwrap_or(attributes.len());
        let (name, rest) = attributes.split_at(name_end);
        let Some(rest) = rest.trim_start_matches(is_xml_space).strip_prefix('=') else {
            return Ok(());
        };
        let rest = rest.trim_start_matches(is_xml_space);
        let Some(quote) = rest.chars().next().filter(|c| matches!(c, '\'' | '"')) else {
            return Ok(());
        };
        let value_start = &rest[1..];
        let Some(value_end) = value_start.find(quote) else {
            return Ok(());
        };
        let value = &value_start[..value_end];
        if name == "encoding" {
            check_encoding(value, encoding)?;
        }
        attributes = &value_start[value_end + 1..];
    }
}

/// Reports whether a character belongs to XML's four-character whitespace set.
fn is_xml_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

/// Compares the declaration's Unicode encoding label to the detected encoding.
///
/// # Errors
///
/// Returns [`Error::Encoding`] for unsupported labels or conflicting encodings.
fn check_encoding(label: &str, encoding: TextEncoding) -> Result<(), Error> {
    let matches = match label.to_ascii_lowercase().as_str() {
        "utf-8" | "utf8" => encoding == TextEncoding::Utf8,
        "utf-16" | "utf16" => matches!(encoding, TextEncoding::Utf16Le | TextEncoding::Utf16Be),
        "utf-16le" => encoding == TextEncoding::Utf16Le,
        "utf-16be" => encoding == TextEncoding::Utf16Be,
        _ => {
            return Err(Error::Encoding(format!(
                "unsupported XML encoding {label:?}; expected UTF-8 or UTF-16"
            )));
        }
    };
    if matches {
        Ok(())
    } else {
        Err(Error::Encoding(format!(
            "XML encoding {label:?} conflicts with detected {encoding:?} bytes"
        )))
    }
}

/// Regression tests for Unicode decoding and declaration consistency.
#[cfg(test)]
mod tests {
    use super::decode;

    /// Encodes test XML as UTF-16 in the requested byte order.
    fn utf16(text: &str, little_endian: bool, with_bom: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        if with_bom {
            bytes.extend(if little_endian {
                [0xff, 0xfe]
            } else {
                [0xfe, 0xff]
            });
        }
        for unit in text.encode_utf16() {
            bytes.extend(if little_endian {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            });
        }
        bytes
    }

    /// UTF-8 input is borrowed, with its optional BOM removed.
    #[test]
    fn utf8_with_and_without_bom() {
        let text = "<?xml version='1.0' encoding='UTF-8'?><a>£🦀</a>";
        assert_eq!(decode(text.as_bytes()).unwrap(), text);
        let mut bytes = vec![0xef, 0xbb, 0xbf];
        bytes.extend(text.as_bytes());
        assert_eq!(decode(&bytes).unwrap(), text);
    }

    /// UTF-16 can be detected from either a BOM or an initial XML declaration.
    #[test]
    fn utf16_with_bom_and_xml_signature() {
        let text = "<?xml version='1.0' encoding='UTF-16'?><a>£🦀�</a>";
        for little_endian in [false, true] {
            for with_bom in [false, true] {
                assert_eq!(decode(&utf16(text, little_endian, with_bom)).unwrap(), text);
            }
        }
    }

    /// Endian-specific declarations must agree with the actual UTF-16 encoding.
    #[test]
    fn endian_specific_declarations() {
        for (little_endian, label) in [(true, "UTF-16LE"), (false, "UTF-16BE")] {
            let text = format!("<?xml version='1.0' encoding='{label}'?><a/>");
            assert_eq!(decode(&utf16(&text, little_endian, true)).unwrap(), text);
            assert!(decode(&utf16(&text, !little_endian, true)).is_err());
        }
    }

    /// Malformed byte sequences are rejected rather than repaired.
    #[test]
    fn malformed_unicode() {
        assert!(decode(&[0xff]).is_err());
        assert!(decode(&[0xef, 0xbb, 0xbf, 0xc0, 0xaf]).is_err());
        assert!(decode(&[0xff, 0xfe, b'<']).is_err());
        assert!(decode(&[0xff, 0xfe, 0, 0xd8]).is_err());
        assert!(decode(&[0xfe, 0xff, 0xdc, 0]).is_err());
    }

    /// UTF-32 is rejected explicitly before a partial UTF-16 BOM can match.
    #[test]
    fn unsupported_utf32() {
        for bytes in [
            [0, 0, 0xfe, 0xff],
            [0xff, 0xfe, 0, 0],
            [0, 0, 0, b'<'],
            [b'<', 0, 0, 0],
        ] {
            let error = decode(&bytes).unwrap_err().to_string();
            assert!(error.contains("UTF-32"), "{error}");
        }
    }

    /// ASCII-only XML still cannot claim an unsupported byte encoding.
    #[test]
    fn unsupported_declaration() {
        assert!(decode(b"<?xml version='1.0' encoding='windows-1252'?><a/>").is_err());
    }

    /// UTF-8 bytes cannot claim UTF-16, even when every character is ASCII.
    #[test]
    fn conflicting_declaration() {
        assert!(decode(b"<?xml version='1.0' encoding='UTF-16'?><a/>").is_err());
        let text = "<?xml version='1.0' encoding='UTF-8'?><a/>";
        assert!(decode(&utf16(text, true, true)).is_err());
    }

    /// Both XML quotation styles and whitespace around equals are accepted.
    #[test]
    fn declaration_whitespace_and_case() {
        let text = "<?xml\tversion = \"1.0\"\nencoding = 'uTf-8' ?><a/>";
        assert_eq!(decode(text.as_bytes()).unwrap(), text);
    }

    /// A processing instruction whose target starts with xml is not a declaration.
    #[test]
    fn stylesheet_is_not_declaration() {
        let text = "<?xml-stylesheet encoding='unsupported' ?><a/>";
        assert_eq!(decode(text.as_bytes()).unwrap(), text);
    }

    /// An encoding-like fragment inside another attribute is not inspected.
    #[test]
    fn encoding_text_in_another_attribute() {
        let text = "<?xml version=\"encoding='unsupported'\"?><a/>";
        assert_eq!(decode(text.as_bytes()).unwrap(), text);
    }
}
