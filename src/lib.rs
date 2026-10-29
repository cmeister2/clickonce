//! Parse ClickOnce deployment (`.application`) and application (`.manifest`) XML.
//!
//! Namespace prefixes are arbitrary. Typed metadata is extracted using namespace
//! URIs; the decoded source remains available for signatures and extensions.
//! Parsing does not verify signatures, hashes, trust, or deployment validity.
//!
//! ```
//! use clickonce::{Manifest, ManifestKind};
//!
//! let manifest = Manifest::from_bytes(include_bytes!("../fixtures/MTGO.application"))?;
//! assert_eq!(manifest.kind, ManifestKind::Deployment);
//! assert_eq!(manifest.identity.name, "MTGO.application");
//! # Ok::<(), clickonce::Error>(())
//! ```

mod encoding;
mod error;
mod model;
mod parser;
mod value;

pub use error::Error;
pub use model::*;
pub use value::*;

use std::io::Read;
use std::path::Path;

/// Limits applied before and during XML parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseOptions {
    /// Maximum size of both the encoded input and the decoded UTF-8 source.
    pub max_input_bytes: usize,
    /// Maximum number of XML nodes, including text and comments.
    pub max_nodes: u32,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024 * 1024,
            max_nodes: 250_000,
        }
    }
}

impl ParseOptions {
    /// Parse an already decoded XML string with these limits.
    ///
    /// # Errors
    /// Returns an error for exceeded limits, malformed XML, an unsupported root,
    /// missing essential fields, duplicate singleton elements, or invalid values.
    pub fn parse(self, xml: &str) -> Result<Manifest, Error> {
        self.check_size(xml.len())?;
        parser::parse(xml, self)
    }

    /// Decode UTF-8 or UTF-16 XML bytes and parse with these limits.
    ///
    /// # Errors
    /// Returns encoding errors for malformed bytes or unsupported or conflicting
    /// encoding declarations, and the errors described by [`Self::parse`].
    pub fn from_bytes(self, bytes: &[u8]) -> Result<Manifest, Error> {
        self.check_size(bytes.len())?;
        self.parse(&encoding::decode(bytes)?)
    }

    /// Read at most the input limit plus one byte, then decode and parse.
    ///
    /// # Errors
    /// Returns read failures, exceeded limits, or errors from [`Self::from_bytes`].
    pub fn from_reader(self, reader: impl Read) -> Result<Manifest, Error> {
        let limit = u64::try_from(self.max_input_bytes).unwrap_or(u64::MAX);
        let mut bytes = Vec::new();
        reader
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)?;
        self.from_bytes(&bytes)
    }

    /// Reject input exceeding the configured byte budget.
    fn check_size(self, size: usize) -> Result<(), Error> {
        if size > self.max_input_bytes {
            return Err(Error::InputTooLarge {
                limit: self.max_input_bytes,
            });
        }
        Ok(())
    }
}

/// An owned snapshot of a ClickOnce manifest's metadata.
///
/// Optional elements remain optional; this parser does not perform XSD validation.
/// With the `serde` feature, metadata can be serialized and deserialized. Source
/// XML is excluded, so a deserialized snapshot has no [`Self::xml`] source.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Manifest {
    /// Classification based on the deployment or application marker.
    pub kind: ManifestKind,
    /// Manifest format version, ordinarily `1.0`.
    pub manifest_version: String,
    /// Identity of the top-level assembly, excluding embedded signature identities.
    pub identity: AssemblyIdentity,
    /// Human-readable application information.
    pub description: Option<Description>,
    /// Deployment and update settings, when present.
    pub deployment: Option<Deployment>,
    /// Compatible frameworks in their declared preference order.
    pub frameworks: Vec<CompatibleFramework>,
    /// Download location advertised by the compatible-framework list.
    pub frameworks_support_url: Option<String>,
    /// Assembly and operating-system dependencies, in document order.
    pub dependencies: Vec<Dependency>,
    /// Nonassembly application files, in document order.
    pub files: Vec<File>,
    /// Application entry point, when present.
    pub entry_point: Option<EntryPoint>,
    /// Claimed publisher identity; its presence does not establish trust.
    pub publisher_identity: Option<PublisherIdentity>,
    /// File associations declared by the application.
    pub file_associations: Vec<FileAssociation>,
    /// Error-reporting URI, preserved as written.
    pub custom_error_report_url: Option<String>,
    /// Whether a top-level XML Signature element is present; it is not verified.
    pub has_signature: bool,
    /// Decoded source, absent on metadata reconstructed through Serde.
    #[cfg_attr(feature = "serde", serde(skip))]
    source: Option<String>,
    /// Limits used when reparsing the retained XML for extension access.
    #[cfg_attr(feature = "serde", serde(skip))]
    options: ParseOptions,
}

impl Manifest {
    /// Parse already decoded XML using the default limits.
    ///
    /// # Errors
    /// Returns the errors described by [`ParseOptions::parse`].
    pub fn parse(xml: &str) -> Result<Self, Error> {
        ParseOptions::default().parse(xml)
    }

    /// Decode and parse UTF-8 or UTF-16 bytes using the default limits.
    ///
    /// # Errors
    /// Returns the errors described by [`ParseOptions::from_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        ParseOptions::default().from_bytes(bytes)
    }

    /// Read, decode and parse XML using the default limits.
    ///
    /// # Errors
    /// Returns the errors described by [`ParseOptions::from_reader`].
    pub fn from_reader(reader: impl Read) -> Result<Self, Error> {
        ParseOptions::default().from_reader(reader)
    }

    /// Open a local file and parse it using the default limits.
    ///
    /// # Errors
    /// Returns file-open failures or errors from [`Self::from_reader`].
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::from_reader(std::fs::File::open(path)?)
    }

    /// Return the decoded XML, including unmodeled elements and signatures.
    ///
    /// Returns `None` for metadata deserialized through Serde. UTF-16 inputs have
    /// been transcoded; the XML declaration may still name the original encoding.
    pub fn xml(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Parse the retained source into a namespace-aware tree for extension access.
    ///
    /// # Errors
    /// Returns [`Error::NoXmlSource`] for deserialized metadata, or an XML error.
    pub fn document(&self) -> Result<roxmltree::Document<'_>, Error> {
        let source = self.xml().ok_or(Error::NoXmlSource)?;
        Ok(roxmltree::Document::parse_with_options(
            source,
            self.options.xml_options(),
        )?)
    }
}

impl ParseOptions {
    /// Translate limits into XML parser options without enabling DTD resolution.
    fn xml_options<'input>(self) -> roxmltree::ParsingOptions<'input> {
        roxmltree::ParsingOptions {
            nodes_limit: self.max_nodes,
            ..roxmltree::ParsingOptions::default()
        }
    }
}
