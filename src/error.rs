//! Errors produced while reading and parsing a manifest.

use std::fmt;

/// A manifest could not be read, decoded, or interpreted.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An input stream or local file could not be read.
    Io(std::io::Error),
    /// The XML is malformed, contains a forbidden DTD, or exceeds the node limit.
    Xml(roxmltree::Error),
    /// The byte encoding is malformed, unsupported, or inconsistent.
    Encoding(String),
    /// The encoded input or decoded source exceeds the configured byte limit.
    InputTooLarge {
        /// Configured maximum size in bytes.
        limit: usize,
    },
    /// The root is not an assembly in a supported Microsoft assembly namespace.
    InvalidRoot,
    /// An essential attribute is absent.
    MissingAttribute {
        /// Element containing the absent attribute.
        element: String,
        /// Required attribute name.
        attribute: String,
    },
    /// An essential child element is absent.
    MissingElement {
        /// Parent element name.
        parent: String,
        /// Required child element name.
        element: String,
    },
    /// A recognized singleton element occurs more than once.
    DuplicateElement {
        /// Parent element name.
        parent: String,
        /// Repeated child element name.
        element: String,
    },
    /// A recognized attribute has an invalid value for its type.
    InvalidAttribute {
        /// Element carrying the attribute.
        element: String,
        /// Attribute name.
        attribute: String,
        /// Invalid source value.
        value: String,
    },
    /// Recognized elements form an ambiguous or contradictory structure.
    InvalidStructure(String),
    /// A typed value such as a version, token, or digest could not be parsed.
    Value(crate::ValueParseError),
    /// Metadata deserialized through Serde has no retained XML source.
    NoXmlSource,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cannot read manifest: {error}"),
            Self::Xml(error) => write!(f, "invalid manifest XML: {error}"),
            Self::Encoding(message) => write!(f, "invalid XML encoding: {message}"),
            Self::InputTooLarge { limit } => write!(f, "manifest exceeds {limit} bytes"),
            Self::InvalidRoot => f.write_str("expected a Microsoft assembly root element"),
            Self::MissingAttribute { element, attribute } => {
                write!(f, "<{element}> is missing attribute {attribute}")
            }
            Self::MissingElement { parent, element } => {
                write!(f, "<{parent}> is missing child <{element}>")
            }
            Self::DuplicateElement { parent, element } => {
                write!(f, "<{parent}> contains duplicate <{element}> elements")
            }
            Self::InvalidAttribute {
                element,
                attribute,
                value,
            } => {
                write!(f, "invalid {attribute} value {value:?} on <{element}>")
            }
            Self::InvalidStructure(message) => f.write_str(message),
            Self::Value(error) => error.fmt(f),
            Self::NoXmlSource => f.write_str("deserialized metadata has no source XML"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Xml(error) => Some(error),
            Self::Value(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<roxmltree::Error> for Error {
    fn from(error: roxmltree::Error) -> Self {
        Self::Xml(error)
    }
}

impl From<crate::ValueParseError> for Error {
    fn from(error: crate::ValueParseError) -> Self {
        Self::Value(error)
    }
}
