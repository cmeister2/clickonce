//! Owned metadata extracted from ClickOnce deployment and application manifests.
//!
//! These types describe the manifest's declared values. They do not establish
//! that a deployment is installable or that its signatures and hashes are valid.
//! Extensible values such as processor architectures and digest algorithms keep
//! unrecognized spellings through their value types.

use crate::value::{
    AssemblyVersion, DependencyType, DigestAlgorithm, DigestValue, FrameworkVersion, HashTransform,
    ProcessorArchitecture, PublicKeyToken, UpdateUnit,
};

/// The role indicated by an assembly manifest's direct child elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ManifestKind {
    /// A deployment manifest, normally stored in a `.application` file.
    Deployment,
    /// An application manifest, normally stored in an `.exe.manifest` file.
    Application,
    /// An assembly manifest without a deployment or application marker.
    ///
    /// This classification preserves legacy or partial manifests without
    /// inferring their role from the filename alone.
    Assembly,
}

/// The identity of a deployment, application, or referenced assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AssemblyIdentity {
    /// The assembly's declared name.
    pub name: String,
    /// The four-part Windows assembly version.
    pub version: Option<AssemblyVersion>,
    /// The public key token declared by the manifest.
    pub public_key_token: Option<PublicKeyToken>,
    /// The processor architecture, including unrecognized architecture names.
    pub processor_architecture: Option<ProcessorArchitecture>,
    /// The language or culture declared for the assembly.
    pub language: Option<String>,
    /// The assembly's `type` attribute, such as `win32`.
    pub assembly_type: Option<String>,
}

/// Display and support information declared by a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Description {
    /// The publisher name used by the Windows shell.
    pub publisher: Option<String>,
    /// The product name displayed to the user.
    pub product: Option<String>,
    /// The optional suite or Start menu subfolder name.
    pub suite_name: Option<String>,
    /// The declared application support location.
    pub support_url: Option<String>,
    /// The application icon filename declared by the manifest.
    pub icon_file: Option<String>,
    /// The description element's text content.
    pub text: String,
}

/// Installation, activation, and update settings from a deployment manifest.
///
/// Optional booleans preserve the difference between an omitted attribute and
/// an explicitly declared value. Applying runtime defaults is the caller's
/// responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Deployment {
    /// Whether the deployment requests installation into the Windows shell.
    pub install: Option<bool>,
    /// The minimum application version accepted by the deployment.
    pub minimum_required_version: Option<AssemblyVersion>,
    /// Whether downloadable payload filenames use the `.deploy` extension.
    pub map_file_extensions: Option<bool>,
    /// Whether activation through the deployment URL is disabled.
    pub disallow_url_activation: Option<bool>,
    /// Whether activation URL parameters may be passed to the application.
    pub trust_url_parameters: Option<bool>,
    /// Whether installation requests a desktop shortcut.
    pub create_desktop_shortcut: Option<bool>,
    /// The deployment provider's codebase, retained as URL or Windows path text.
    pub provider: Option<String>,
    /// The automatic update policy, when a subscription declares one.
    pub update: Option<UpdatePolicy>,
}

/// The update check behavior declared by a deployment subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum UpdatePolicy {
    /// Check for an update before the application starts.
    BeforeApplicationStartup,
    /// Check for updates in the background after the declared interval.
    Background {
        /// The maximum age of a previous update check in the declared unit.
        maximum_age: u64,
        /// The update interval unit.
        unit: UpdateUnit,
    },
}

/// One compatible .NET Framework declaration, in manifest preference order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CompatibleFramework {
    /// The target .NET Framework version.
    pub target_version: FrameworkVersion,
    /// The framework profile, such as `Client` or `Full`.
    pub profile: Option<String>,
    /// The associated common language runtime version.
    pub supported_runtime: Option<FrameworkVersion>,
}

/// An assembly or operating system prerequisite declared by a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Dependency {
    /// A referenced assembly or application manifest.
    Assembly(AssemblyDependency),
    /// An operating system requirement.
    OperatingSystem(OperatingSystemDependency),
}

/// A dependency on another assembly or on the application's versioned manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AssemblyDependency {
    /// The identity expected for the referenced assembly.
    pub identity: AssemblyIdentity,
    /// The dependency relationship, such as `install` or `preRequisite`.
    pub dependency_type: Option<DependencyType>,
    /// The dependency's URL or Windows path, without path normalization.
    pub codebase: Option<String>,
    /// The declared dependency size in bytes.
    pub size: Option<u64>,
    /// The optional download group containing this dependency.
    pub group: Option<String>,
    /// Whether the dependency may be downloaded on demand.
    pub optional: Option<bool>,
    /// Whether dependency binding may be delayed until the assembly is used.
    pub allow_delayed_binding: Option<bool>,
    /// The legacy `preRequisite` flag, when explicitly declared.
    pub prerequisite: Option<bool>,
    /// Whether this dependency is exposed as a top-level application identity.
    pub visible: Option<bool>,
    /// The declared dependency digests and transformations, in document order.
    pub hashes: Vec<Hash>,
}

/// A declared operating system requirement.
///
/// Version components are unsigned integers. Their presence describes the
/// manifest's requirement without assessing the host's compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OperatingSystemDependency {
    /// A location offering support for the required operating system.
    pub support_url: Option<String>,
    /// A human-readable description of the operating system requirement.
    pub description: Option<String>,
    /// The minimum operating system major version.
    pub major_version: Option<u32>,
    /// The minimum operating system minor version.
    pub minor_version: Option<u32>,
    /// The minimum operating system build number.
    pub build_number: Option<u32>,
    /// The minimum service pack major version.
    pub service_pack_major: Option<u32>,
    /// The minimum service pack minor version.
    pub service_pack_minor: Option<u32>,
    /// The operating system product type declared by the requirement.
    pub product_type: Option<String>,
    /// The operating system suite type declared by the requirement.
    pub suite_type: Option<String>,
}

/// A manifest's declared file digest.
///
/// Reading this metadata does not calculate or verify a digest. Algorithms,
/// transforms, and the parsed digest remain available to a separate verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Hash {
    /// Transformation algorithms, in their declared order.
    pub transforms: Vec<HashTransform>,
    /// The digest algorithm, including unrecognized algorithm URIs.
    pub digest_method: DigestAlgorithm,
    /// The parsed digest value.
    pub digest_value: DigestValue,
}

/// A nonassembly payload file listed in an application manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct File {
    /// The declared filename, retained without platform-specific normalization.
    pub name: String,
    /// The declared file size in bytes.
    pub size: Option<u64>,
    /// The optional download group containing the file.
    pub group: Option<String>,
    /// Whether the file may be downloaded on demand.
    pub optional: Option<bool>,
    /// The declared `writeableType` value, such as `applicationData`.
    pub writeable_type: Option<String>,
    /// The declared file digests and transformations, in document order.
    pub hashes: Vec<Hash>,
}

/// The application code entry point or a custom host declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EntryPoint {
    /// The optional entry point name.
    pub name: Option<String>,
    /// The identity of the assembly that provides the entry point.
    pub identity: Option<AssemblyIdentity>,
    /// The executable and parameter text declared for activation.
    pub command_line: Option<CommandLine>,
    /// Whether activation requires a custom host.
    pub custom_host_required: bool,
    /// Whether the application declares custom activation user interface.
    pub custom_ux: bool,
}

/// An executable filename and its uninterpreted activation parameter text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CommandLine {
    /// The executable filename declared by the manifest.
    pub file: String,
    /// The parameter text, without shell expansion or argument splitting.
    pub parameters: Option<String>,
}

/// Publisher metadata associated with a signed manifest.
///
/// These values are declarations and do not imply certificate validation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublisherIdentity {
    /// The publisher name, typically an X.509 distinguished name.
    pub name: String,
    /// The hash of the issuer key declared by the manifest.
    pub issuer_key_hash: Option<String>,
}

/// A file extension association requested by an application manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FileAssociation {
    /// The associated file extension.
    pub extension: String,
    /// The user-facing description of the file type.
    pub description: Option<String>,
    /// The programmatic identifier registered for the file type.
    pub progid: Option<String>,
    /// The icon declaration used for the associated file type.
    pub default_icon: Option<String>,
}
