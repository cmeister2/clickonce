//! Validated scalar values and extensible vocabularies used by manifests.

use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// An invalid textual representation of a manifest value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueParseError {
    /// The category of value that could not be parsed.
    pub kind: &'static str,
    /// The original invalid input.
    pub value: String,
}

impl ValueParseError {
    /// Create a parse error for an invalid manifest value.
    pub(crate) fn new(kind: &'static str, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
}

impl fmt::Display for ValueParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid {}: {:?}", self.kind, self.value)
    }
}

impl std::error::Error for ValueParseError {}

/// A four-component Windows assembly version.
///
/// Each component is an unsigned 16-bit integer. This is a Windows assembly
/// version, rather than a Semantic Versioning version with prerelease metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct AssemblyVersion {
    /// The major version component.
    pub major: u16,
    /// The minor version component.
    pub minor: u16,
    /// The build version component.
    pub build: u16,
    /// The revision version component.
    pub revision: u16,
}

impl FromStr for AssemblyVersion {
    type Err = ValueParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts = parse_components(value, "assembly version", 4, 4)?;
        Ok(Self {
            major: parts[0],
            minor: parts[1],
            build: parts[2],
            revision: parts[3],
        })
    }
}

impl fmt::Display for AssemblyVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}.{}.{}.{}",
            self.major, self.minor, self.build, self.revision
        )
    }
}

/// A .NET Framework or runtime version containing two to four components.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct FrameworkVersion {
    /// The validated version components, preserving the declared component count.
    components: Vec<u16>,
}

impl FrameworkVersion {
    /// Return the version's two to four numeric components.
    pub fn components(&self) -> &[u16] {
        &self.components
    }
}

impl FromStr for FrameworkVersion {
    type Err = ValueParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            components: parse_components(value, "framework version", 2, 4)?,
        })
    }
}

impl fmt::Display for FrameworkVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, component) in self.components.iter().enumerate() {
            if index != 0 {
                formatter.write_str(".")?;
            }
            write!(formatter, "{component}")?;
        }
        Ok(())
    }
}

/// An eight-byte assembly public key token, encoded as 16 hexadecimal digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct PublicKeyToken {
    /// The eight decoded token bytes in their declared order.
    bytes: [u8; 8],
}

impl PublicKeyToken {
    /// Return the eight decoded token bytes.
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.bytes
    }
}

impl FromStr for PublicKeyToken {
    type Err = ValueParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 16 {
            return Err(ValueParseError::new("public key token", value));
        }
        let mut bytes = [0_u8; 8];
        for (byte, digits) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let high = hex_digit(digits[0])
                .ok_or_else(|| ValueParseError::new("public key token", value))?;
            let low = hex_digit(digits[1])
                .ok_or_else(|| ValueParseError::new("public key token", value))?;
            *byte = (high << 4) | low;
        }
        Ok(Self { bytes })
    }
}

impl fmt::Display for PublicKeyToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.bytes {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A decoded base64 digest declared by a manifest.
///
/// Parsing ignores XML whitespace and checks base64 syntax. It does not check
/// the digest's length against its separately declared algorithm or verify a
/// payload. Display and Serde produce standard padded base64 without whitespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String", into = "String"))]
pub struct DigestValue {
    /// The decoded digest bytes.
    bytes: Vec<u8>,
}

impl DigestValue {
    /// Return the decoded digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl FromStr for DigestValue {
    type Err = ValueParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let compact: Vec<u8> = value
            .bytes()
            .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            .collect();
        let bytes = STANDARD
            .decode(compact)
            .map_err(|_| ValueParseError::new("base64 digest", value))?;
        Ok(Self { bytes })
    }
}

impl fmt::Display for DigestValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&STANDARD.encode(&self.bytes))
    }
}

/// Implement owned-string conversions for a validated textual value.
macro_rules! parsed_string_conversions {
    ($value_type:ty) => {
        impl TryFrom<String> for $value_type {
            type Error = ValueParseError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                value.parse()
            }
        }

        impl From<$value_type> for String {
            fn from(value: $value_type) -> Self {
                value.to_string()
            }
        }
    };
}

parsed_string_conversions!(AssemblyVersion);
parsed_string_conversions!(FrameworkVersion);
parsed_string_conversions!(PublicKeyToken);
parsed_string_conversions!(DigestValue);

/// Define an extensible manifest vocabulary with string-based conversion.
macro_rules! text_enum {
    (
        $(#[$enum_attribute:meta])*
        pub enum $enum_name:ident {
            $(
                $(#[$variant_attribute:meta])*
                $variant:ident => $spelling:literal $(| $alias:literal)*
            ),+ $(,)?
        }
    ) => {
        $(#[$enum_attribute])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(from = "String", into = "String"))]
        #[non_exhaustive]
        pub enum $enum_name {
            $(
                $(#[$variant_attribute])*
                $variant,
            )+
            /// An unrecognized value, retained without normalization.
            Other(String),
        }

        impl From<&str> for $enum_name {
            fn from(value: &str) -> Self {
                match value {
                    $($spelling $(| $alias)* => Self::$variant,)+
                    other => Self::Other(other.to_owned()),
                }
            }
        }

        impl From<String> for $enum_name {
            fn from(value: String) -> Self {
                match value.as_str() {
                    $($spelling $(| $alias)* => Self::$variant,)+
                    _ => Self::Other(value),
                }
            }
        }

        impl fmt::Display for $enum_name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(Self::$variant => formatter.write_str($spelling),)+
                    Self::Other(value) => formatter.write_str(value),
                }
            }
        }

        impl From<$enum_name> for String {
            fn from(value: $enum_name) -> Self {
                value.to_string()
            }
        }
    };
}

text_enum! {
    /// A processor architecture declared by an assembly identity.
    pub enum ProcessorArchitecture {
        /// Managed intermediate language usable across processor architectures.
        Msil => "msil",
        /// The 32-bit x86 architecture.
        X86 => "x86",
        /// The 64-bit x86 architecture.
        Amd64 => "amd64" | "AMD64",
        /// The 32-bit ARM architecture.
        Arm => "arm" | "ARM",
        /// The 64-bit ARM architecture.
        Arm64 => "arm64" | "ARM64",
        /// The Intel Itanium architecture.
        Ia64 => "ia64" | "IA64",
        /// Any processor architecture.
        Wildcard => "*",
    }
}

text_enum! {
    /// The relationship between an assembly dependency and its application.
    pub enum DependencyType {
        /// An assembly or manifest installed with the application.
        Install => "install",
        /// An assembly that must already be available on the client.
        Prerequisite => "preRequisite",
    }
}

text_enum! {
    /// A time unit for background update checks.
    pub enum UpdateUnit {
        /// An interval measured in hours.
        Hours => "hours",
        /// An interval measured in days.
        Days => "days",
        /// An interval measured in weeks.
        Weeks => "weeks",
    }
}

text_enum! {
    /// A file digest algorithm identified by an XML algorithm URI.
    ///
    /// Known legacy ClickOnce SHA-2 URI spellings are recognized alongside the
    /// standard XML Signature and XML Encryption spellings. Display emits the
    /// standard URI; the original manifest XML retains the original spelling.
    pub enum DigestAlgorithm {
        /// The SHA-1 digest algorithm.
        Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
        /// The SHA-256 digest algorithm.
        Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256"
            | "http://www.w3.org/2000/09/xmldsig#sha256",
        /// The SHA-384 digest algorithm.
        Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384"
            | "http://www.w3.org/2000/09/xmldsig#sha384",
        /// The SHA-512 digest algorithm.
        Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512"
            | "http://www.w3.org/2000/09/xmldsig#sha512",
    }
}

text_enum! {
    /// A transformation applied before calculating a file digest.
    pub enum HashTransform {
        /// Hash the payload without transforming its bytes.
        Identity => "urn:schemas-microsoft-com:HashTransforms.Identity",
    }
}

/// Parse a bounded count of unsigned decimal 16-bit version components.
fn parse_components(
    value: &str,
    kind: &'static str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u16>, ValueParseError> {
    let mut components = Vec::with_capacity(maximum);
    for part in value.split('.') {
        if components.len() == maximum
            || part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ValueParseError::new(kind, value));
        }
        components.push(
            part.parse()
                .map_err(|_| ValueParseError::new(kind, value))?,
        );
    }
    if components.len() < minimum {
        return Err(ValueParseError::new(kind, value));
    }
    Ok(components)
}

/// Decode one ASCII hexadecimal digit without accepting Unicode lookalikes.
fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! Scalar validation and lexical conversion regression tests.

    use super::*;

    /// Four-part assembly versions retain numeric ordering and reject invalid input.
    #[test]
    fn assembly_versions_validate_components() {
        let version: AssemblyVersion = "3.4.159.4708".parse().unwrap();
        assert_eq!(version.major, 3);
        assert_eq!(version.minor, 4);
        assert_eq!(version.build, 159);
        assert_eq!(version.revision, 4708);
        assert_eq!(version.to_string(), "3.4.159.4708");
        assert!("4.0.0.0".parse::<AssemblyVersion>().unwrap() > version);
        assert!("65535.0.0.65535".parse::<AssemblyVersion>().is_ok());
        for invalid in [
            "",
            "1.2.3",
            "1.2.3.4.5",
            "65536.0.0.0",
            "+1.2.3.4",
            "1.-2.3.4",
            "1..3.4",
            "1.2.3.4 ",
            "１.2.3.4",
            "1.2.3.4-beta",
        ] {
            assert!(invalid.parse::<AssemblyVersion>().is_err(), "{invalid:?}");
        }
    }

    /// Framework and runtime versions permit two, three, or four components.
    #[test]
    fn framework_versions_preserve_component_count() {
        for text in ["4.0", "4.7.2", "4.0.30319", "1.2.3.4"] {
            let version: FrameworkVersion = text.parse().unwrap();
            assert_eq!(version.to_string(), text);
            assert_eq!(version.components().len(), text.split('.').count());
        }
        for invalid in ["4", "4.0.0.0.0", "v4.0", "4.65536", "4.0."] {
            assert!(invalid.parse::<FrameworkVersion>().is_err(), "{invalid:?}");
        }
    }

    /// Public key tokens decode hex case-insensitively and display canonical hex.
    #[test]
    fn public_key_tokens_validate_hexadecimal_bytes() {
        let token: PublicKeyToken = "A2d3B1cd60f98833".parse().unwrap();
        assert_eq!(
            token.as_bytes(),
            &[0xa2, 0xd3, 0xb1, 0xcd, 0x60, 0xf9, 0x88, 0x33]
        );
        assert_eq!(token.to_string(), "a2d3b1cd60f98833");
        for invalid in [
            "",
            "a2d3b1cd60f9883",
            "a2d3b1cd60f988330",
            "g2d3b1cd60f98833",
            "é23456789012345",
        ] {
            assert!(invalid.parse::<PublicKeyToken>().is_err(), "{invalid:?}");
        }
    }

    /// Digests validate padding and ignore only XML's four whitespace characters.
    #[test]
    fn digests_validate_base64_and_decode_bytes() {
        let digest: DigestValue = " YW\tJj\r\nZA== ".parse().unwrap();
        assert_eq!(digest.as_bytes(), b"abcd");
        assert_eq!(digest.to_string(), "YWJjZA==");
        assert!("".parse::<DigestValue>().unwrap().as_bytes().is_empty());
        assert!(
            " \t\r\n"
                .parse::<DigestValue>()
                .unwrap()
                .as_bytes()
                .is_empty()
        );
        for invalid in ["???", "ZA", "ZA=", "ZE==", "ZA==\u{a0}", "ZA==="] {
            assert!(invalid.parse::<DigestValue>().is_err(), "{invalid:?}");
        }
    }

    /// Extensible vocabularies recognize known values and preserve unknown strings.
    #[test]
    fn vocabularies_preserve_extension_values() {
        assert_eq!(
            ProcessorArchitecture::from("amd64"),
            ProcessorArchitecture::Amd64
        );
        assert_eq!(UpdateUnit::from("hours"), UpdateUnit::Hours);
        assert_eq!(
            DependencyType::from("preRequisite"),
            DependencyType::Prerequisite
        );
        assert_eq!(
            DigestAlgorithm::from("http://www.w3.org/2000/09/xmldsig#sha256"),
            DigestAlgorithm::Sha256
        );
        assert_eq!(
            HashTransform::from("urn:schemas-microsoft-com:HashTransforms.Identity"),
            HashTransform::Identity
        );
        assert_eq!(
            ProcessorArchitecture::from("riscv64").to_string(),
            "riscv64"
        );
        assert_eq!(
            DigestAlgorithm::from("urn:future:hash").to_string(),
            "urn:future:hash"
        );
        assert_eq!(UpdateUnit::from("months").to_string(), "months");
    }

    /// Serde uses stable strings and reapplies validation during deserialization.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_scalars_round_trip_through_strings() {
        let version: AssemblyVersion = "3.4.159.4708".parse().unwrap();
        assert_eq!(serde_json::to_string(&version).unwrap(), "\"3.4.159.4708\"");
        assert_eq!(
            serde_json::from_str::<AssemblyVersion>("\"3.4.159.4708\"").unwrap(),
            version
        );
        assert!(serde_json::from_str::<AssemblyVersion>("\"1.2.3\"").is_err());
        let framework: FrameworkVersion = "4.7.2".parse().unwrap();
        let token: PublicKeyToken = "a2d3b1cd60f98833".parse().unwrap();
        let digest: DigestValue = "YWJjZA==".parse().unwrap();
        assert_eq!(
            serde_json::from_str::<FrameworkVersion>(&serde_json::to_string(&framework).unwrap())
                .unwrap(),
            framework
        );
        assert_eq!(
            serde_json::from_str::<PublicKeyToken>(&serde_json::to_string(&token).unwrap())
                .unwrap(),
            token
        );
        assert_eq!(
            serde_json::from_str::<DigestValue>(&serde_json::to_string(&digest).unwrap()).unwrap(),
            digest
        );
        for architecture in [
            ProcessorArchitecture::Arm64,
            ProcessorArchitecture::from("riscv64"),
        ] {
            assert_eq!(
                serde_json::from_str::<ProcessorArchitecture>(
                    &serde_json::to_string(&architecture).unwrap()
                )
                .unwrap(),
                architecture
            );
        }
        assert_eq!(
            serde_json::to_string(&DependencyType::Prerequisite).unwrap(),
            "\"preRequisite\""
        );
        assert_eq!(
            serde_json::to_string(&UpdateUnit::Hours).unwrap(),
            "\"hours\""
        );
        assert_eq!(
            serde_json::from_str::<DigestAlgorithm>(
                &serde_json::to_string(&DigestAlgorithm::Sha256).unwrap()
            )
            .unwrap(),
            DigestAlgorithm::Sha256
        );
        assert_eq!(
            serde_json::from_str::<HashTransform>(
                &serde_json::to_string(&HashTransform::Identity).unwrap()
            )
            .unwrap(),
            HashTransform::Identity
        );
        assert!(serde_json::from_str::<PublicKeyToken>("\"invalid\"").is_err());
        assert!(serde_json::from_str::<DigestValue>("\"???\"").is_err());
    }
}
