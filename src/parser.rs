//! Namespace-aware extraction of common ClickOnce metadata.

use std::str::FromStr;

use roxmltree::Node;

use crate::*;

/// The original assembly namespace, used for roots and identities.
const ASM_V1: &str = "urn:schemas-microsoft-com:asm.v1";
/// The ClickOnce assembly namespace, used for deployment metadata.
const ASM_V2: &str = "urn:schemas-microsoft-com:asm.v2";
/// The namespace containing desktop shortcut and file association extensions.
const CLICKONCE_V1: &str = "urn:schemas-microsoft-com:clickonce.v1";
/// The namespace containing compatible-framework declarations.
const CLICKONCE_V2: &str = "urn:schemas-microsoft-com:clickonce.v2";
/// The namespace containing digest algorithms and signatures.
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
/// Assembly namespaces accepted for shared elements across manifest generations.
const ASSEMBLY_NAMESPACES: &[&str] = &[ASM_V1, ASM_V2];

/// Extract an owned snapshot after checking XML syntax and resource limits.
pub(crate) fn parse(xml: &str, options: ParseOptions) -> Result<Manifest, Error> {
    let document = roxmltree::Document::parse_with_options(xml, options.xml_options())?;
    let root = document.root_element();
    if !matches_element(root, "assembly", ASSEMBLY_NAMESPACES) {
        return Err(Error::InvalidRoot);
    }
    let identity = identity(required_child(
        root,
        "assemblyIdentity",
        ASSEMBLY_NAMESPACES,
    )?)?;
    let deployment = child(root, "deployment", ASSEMBLY_NAMESPACES)?
        .map(deployment)
        .transpose()?;
    let application = child(root, "application", ASSEMBLY_NAMESPACES)?;
    let entry_point = child(root, "entryPoint", ASSEMBLY_NAMESPACES)?
        .map(entry_point)
        .transpose()?;
    let kind = match (
        deployment.is_some(),
        application.is_some() || entry_point.is_some(),
    ) {
        (true, false) => ManifestKind::Deployment,
        (false, true) => ManifestKind::Application,
        (false, false) => ManifestKind::Assembly,
        (true, true) => {
            return Err(Error::InvalidStructure(
                "an assembly cannot declare both deployment and application metadata".into(),
            ));
        }
    };
    let framework_list = child(root, "compatibleFrameworks", &[CLICKONCE_V2])?;
    let mut frameworks = Vec::new();
    if let Some(list) = framework_list {
        for node in children(list, "framework", &[CLICKONCE_V2]) {
            frameworks.push(CompatibleFramework {
                target_version: required_attribute(node, "targetVersion")?.parse()?,
                profile: attribute(node, "profile"),
                supported_runtime: parsed_attribute(node, "supportedRuntime")?,
            });
        }
    }
    let mut dependencies = Vec::new();
    for node in children(root, "dependency", ASSEMBLY_NAMESPACES) {
        let assembly = child(node, "dependentAssembly", ASSEMBLY_NAMESPACES)?;
        let os = child(node, "dependentOS", ASSEMBLY_NAMESPACES)?;
        match (assembly, os) {
            (Some(node), None) => {
                dependencies.push(Dependency::Assembly(assembly_dependency(node)?))
            }
            (None, Some(node)) => {
                dependencies.push(Dependency::OperatingSystem(os_dependency(node)?))
            }
            (Some(_), Some(_)) => {
                return Err(Error::InvalidStructure(
                    "a dependency cannot declare both dependentAssembly and dependentOS".into(),
                ));
            }
            (None, None) => {
                // Unknown dependency forms remain accessible through retained XML.
            }
        }
    }
    let files = children(root, "file", ASSEMBLY_NAMESPACES)
        .map(file)
        .collect::<Result<_, _>>()?;
    let file_associations = children(root, "fileAssociation", &[CLICKONCE_V1])
        .map(|node| {
            Ok(FileAssociation {
                extension: required_attribute(node, "extension")?.into(),
                description: attribute(node, "description"),
                progid: attribute(node, "progid"),
                default_icon: attribute(node, "defaultIcon"),
            })
        })
        .collect::<Result<_, Error>>()?;
    let publisher_identity = child(root, "publisherIdentity", ASSEMBLY_NAMESPACES)?
        .map(|node| {
            Ok::<_, Error>(PublisherIdentity {
                name: required_attribute(node, "name")?.into(),
                issuer_key_hash: attribute(node, "issuerKeyHash"),
            })
        })
        .transpose()?;
    Ok(Manifest {
        kind,
        manifest_version: required_attribute(root, "manifestVersion")?.into(),
        identity,
        description: child(root, "description", ASSEMBLY_NAMESPACES)?
            .map(description)
            .transpose()?,
        deployment,
        frameworks,
        frameworks_support_url: framework_list
            .map(|node| aliased_attribute(node, &[(None, "SupportUrl"), (None, "supportUrl")]))
            .transpose()?
            .flatten(),
        dependencies,
        files,
        entry_point,
        publisher_identity,
        file_associations,
        custom_error_report_url: child(root, "customErrorReporting", &[CLICKONCE_V1, ASM_V2])?
            .map(|node| aliased_attribute(node, &[(None, "uri"), (None, "Uri")]))
            .transpose()?
            .flatten(),
        has_signature: child(root, "Signature", &[DSIG])?.is_some(),
        source: Some(xml.into()),
        options,
    })
}

/// Match expanded element names, ignoring arbitrary prefix spellings.
fn matches_element(node: Node<'_, '_>, name: &str, namespaces: &[&str]) -> bool {
    node.is_element()
        && node.tag_name().name() == name
        && node
            .tag_name()
            .namespace()
            .is_some_and(|ns| namespaces.contains(&ns))
}

/// Iterate over matching direct children in document order.
fn children<'a, 'input: 'a>(
    node: Node<'a, 'input>,
    name: &'a str,
    namespaces: &'a [&'a str],
) -> impl Iterator<Item = Node<'a, 'input>> + 'a {
    node.children()
        .filter(move |node| matches_element(*node, name, namespaces))
}

/// Find an optional singleton while rejecting ambiguous repeated elements.
fn child<'a, 'input>(
    node: Node<'a, 'input>,
    name: &str,
    namespaces: &[&str],
) -> Result<Option<Node<'a, 'input>>, Error> {
    let mut matches = node
        .children()
        .filter(|node| matches_element(*node, name, namespaces));
    let result = matches.next();
    if matches.next().is_some() {
        return Err(Error::DuplicateElement {
            parent: node.tag_name().name().into(),
            element: name.into(),
        });
    }
    Ok(result)
}

/// Find an essential child element.
fn required_child<'a, 'input>(
    node: Node<'a, 'input>,
    name: &str,
    namespaces: &[&str],
) -> Result<Node<'a, 'input>, Error> {
    child(node, name, namespaces)?.ok_or_else(|| Error::MissingElement {
        parent: node.tag_name().name().into(),
        element: name.into(),
    })
}

/// Read an unqualified optional attribute without accepting foreign namespaces.
fn attribute(node: Node<'_, '_>, name: &str) -> Option<String> {
    unqualified_attribute(node, name).map(str::to_owned)
}

/// Find an attribute with no namespace; roxmltree's string lookup ignores namespaces.
fn unqualified_attribute<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.attributes()
        .find(|attribute| attribute.namespace().is_none() && attribute.name() == name)
        .map(|attribute| attribute.value())
}

/// Read an essential unqualified attribute.
fn required_attribute<'a>(node: Node<'a, '_>, name: &str) -> Result<&'a str, Error> {
    unqualified_attribute(node, name).ok_or_else(|| Error::MissingAttribute {
        element: node.tag_name().name().into(),
        attribute: name.into(),
    })
}

/// Read a documented attribute spelling or namespace alias without ambiguity.
fn aliased_attribute(
    node: Node<'_, '_>,
    aliases: &[(Option<&str>, &str)],
) -> Result<Option<String>, Error> {
    let mut result = None;
    for &(namespace, name) in aliases {
        let value = match namespace {
            Some(ns) => node.attribute((ns, name)),
            None => unqualified_attribute(node, name),
        };
        if let Some(value) = value {
            if result.is_some() {
                return Err(Error::InvalidStructure(format!(
                    "ambiguous attribute aliases for {name} on <{}>",
                    node.tag_name().name(),
                )));
            }
            result = Some(value.into());
        }
    }
    Ok(result)
}

/// Parse a numeric, version, or token attribute while retaining field context.
fn parsed_attribute<T: FromStr>(node: Node<'_, '_>, name: &str) -> Result<Option<T>, Error> {
    unqualified_attribute(node, name)
        .map(|value| parse_attribute_value(node, name, value))
        .transpose()
}

/// Parse a typed attribute, normalizing XML whitespace only for numeric fields.
fn parse_attribute_value<T: FromStr>(
    node: Node<'_, '_>,
    name: &str,
    value: &str,
) -> Result<T, Error> {
    let lexical = if matches!(
        name,
        "size"
            | "maximumAge"
            | "majorVersion"
            | "minorVersion"
            | "buildNumber"
            | "servicePackMajor"
            | "servicePackMinor"
    ) {
        value.trim_matches([' ', '\t', '\r', '\n'])
    } else {
        value
    };
    lexical.parse().map_err(|_| Error::InvalidAttribute {
        element: node.tag_name().name().into(),
        attribute: name.into(),
        value: value.into(),
    })
}

/// Parse the four XML Schema boolean spellings, preserving absence.
fn boolean_attribute(node: Node<'_, '_>, name: &str) -> Result<Option<bool>, Error> {
    unqualified_attribute(node, name)
        .map(|value| boolean_value(node, name, value))
        .transpose()
}

/// Interpret an XML Schema boolean without treating other strings as false.
fn boolean_value(node: Node<'_, '_>, name: &str, value: &str) -> Result<bool, Error> {
    match value.trim() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(Error::InvalidAttribute {
            element: node.tag_name().name().into(),
            attribute: name.into(),
            value: value.into(),
        }),
    }
}

/// Extract the direct assembly identity, never a descendant inside a signature.
fn identity(node: Node<'_, '_>) -> Result<AssemblyIdentity, Error> {
    Ok(AssemblyIdentity {
        name: required_attribute(node, "name")?.into(),
        version: parsed_attribute(node, "version")?,
        public_key_token: parsed_attribute(node, "publicKeyToken")?,
        processor_architecture: unqualified_attribute(node, "processorArchitecture")
            .map(ProcessorArchitecture::from),
        language: aliased_attribute(node, &[(None, "language"), (None, "culture")])?,
        assembly_type: attribute(node, "type"),
    })
}

/// Extract text nodes, including CDATA, without nested extension text.
fn text(node: Node<'_, '_>) -> String {
    node.children()
        .filter_map(|node| node.text().filter(|_| node.is_text()))
        .collect()
}

/// Read description attributes from their documented assembly/ClickOnce namespaces.
fn description(node: Node<'_, '_>) -> Result<Description, Error> {
    /// Find an attribute across documented namespaced and legacy unqualified forms.
    fn display_attribute(node: Node<'_, '_>, name: &str) -> Result<Option<String>, Error> {
        aliased_attribute(
            node,
            &[
                (Some(ASM_V2), name),
                (Some(CLICKONCE_V1), name),
                (None, name),
            ],
        )
    }
    Ok(Description {
        publisher: display_attribute(node, "publisher")?,
        product: display_attribute(node, "product")?,
        suite_name: display_attribute(node, "suiteName")?,
        support_url: display_attribute(node, "supportUrl")?,
        icon_file: display_attribute(node, "iconFile")?,
        text: text(node),
    })
}

/// Parse deployment settings and the optional update subscription.
fn deployment(node: Node<'_, '_>) -> Result<Deployment, Error> {
    let shortcut = node
        .attribute((CLICKONCE_V1, "createDesktopShortcut"))
        .map(|value| boolean_value(node, "createDesktopShortcut", value))
        .transpose()?;
    let trust = aliased_attribute(
        node,
        &[(None, "trustURLParameters"), (None, "trustUrlParameters")],
    )?
    .map(|value| boolean_value(node, "trustURLParameters", &value))
    .transpose()?;
    let update = child(node, "subscription", ASSEMBLY_NAMESPACES)?
        .map(|subscription| {
            update_policy(required_child(subscription, "update", ASSEMBLY_NAMESPACES)?)
        })
        .transpose()?;
    Ok(Deployment {
        install: boolean_attribute(node, "install")?,
        minimum_required_version: parsed_attribute(node, "minimumRequiredVersion")?,
        map_file_extensions: boolean_attribute(node, "mapFileExtensions")?,
        disallow_url_activation: boolean_attribute(node, "disallowUrlActivation")?,
        trust_url_parameters: trust,
        create_desktop_shortcut: shortcut,
        provider: child(node, "deploymentProvider", ASSEMBLY_NAMESPACES)?
            .map(|provider| required_attribute(provider, "codebase").map(str::to_owned))
            .transpose()?,
        update,
    })
}

/// Parse the mutually exclusive startup and background update modes.
fn update_policy(node: Node<'_, '_>) -> Result<UpdatePolicy, Error> {
    let startup = child(node, "beforeApplicationStartup", ASSEMBLY_NAMESPACES)?;
    let expiration = child(node, "expiration", ASSEMBLY_NAMESPACES)?;
    match (startup, expiration) {
        (Some(_), None) => Ok(UpdatePolicy::BeforeApplicationStartup),
        (None, Some(expiration)) => Ok(UpdatePolicy::Background {
            maximum_age: parsed_attribute(expiration, "maximumAge")?.ok_or_else(|| {
                Error::MissingAttribute {
                    element: "expiration".into(),
                    attribute: "maximumAge".into(),
                }
            })?,
            unit: UpdateUnit::from(required_attribute(expiration, "unit")?),
        }),
        _ => Err(Error::InvalidStructure(
            "update requires exactly one of beforeApplicationStartup or expiration".into(),
        )),
    }
}

/// Extract an assembly dependency with optional digest metadata.
fn assembly_dependency(node: Node<'_, '_>) -> Result<AssemblyDependency, Error> {
    Ok(AssemblyDependency {
        identity: identity(required_child(
            node,
            "assemblyIdentity",
            ASSEMBLY_NAMESPACES,
        )?)?,
        dependency_type: unqualified_attribute(node, "dependencyType").map(DependencyType::from),
        codebase: aliased_attribute(node, &[(None, "codebase"), (None, "codeBase")])?,
        size: parsed_attribute(node, "size")?,
        group: attribute(node, "group"),
        optional: boolean_attribute(node, "optional")?,
        allow_delayed_binding: boolean_attribute(node, "allowDelayedBinding")?,
        prerequisite: boolean_attribute(node, "preRequisite")?,
        visible: boolean_attribute(node, "visible")?,
        hashes: children(node, "hash", ASSEMBLY_NAMESPACES)
            .map(hash)
            .collect::<Result<_, _>>()?,
    })
}

/// Extract numeric operating system version requirements when declared.
fn os_dependency(node: Node<'_, '_>) -> Result<OperatingSystemDependency, Error> {
    let os = child(node, "osVersionInfo", ASSEMBLY_NAMESPACES)?
        .map(|version| child(version, "os", ASSEMBLY_NAMESPACES))
        .transpose()?
        .flatten();
    /// Read a numeric operating system component only when its element exists.
    fn component(os: Option<Node<'_, '_>>, name: &str) -> Result<Option<u32>, Error> {
        os.map(|node| parsed_attribute(node, name))
            .transpose()
            .map(Option::flatten)
    }
    Ok(OperatingSystemDependency {
        support_url: attribute(node, "supportUrl"),
        description: attribute(node, "description"),
        major_version: component(os, "majorVersion")?,
        minor_version: component(os, "minorVersion")?,
        build_number: component(os, "buildNumber")?,
        service_pack_major: component(os, "servicePackMajor")?,
        service_pack_minor: component(os, "servicePackMinor")?,
        product_type: os.and_then(|node| attribute(node, "productType")),
        suite_type: os.and_then(|node| attribute(node, "suiteType")),
    })
}

/// Decode a file digest and retain extensible algorithm declarations.
fn hash(node: Node<'_, '_>) -> Result<Hash, Error> {
    let transforms = child(node, "Transforms", &[DSIG])?
        .map(|transforms| {
            children(transforms, "Transform", &[DSIG])
                .map(|transform| {
                    required_attribute(transform, "Algorithm").map(HashTransform::from)
                })
                .collect::<Result<_, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(Hash {
        transforms,
        digest_method: DigestAlgorithm::from(required_attribute(
            required_child(node, "DigestMethod", &[DSIG])?,
            "Algorithm",
        )?),
        digest_value: text(required_child(node, "DigestValue", &[DSIG])?).parse()?,
    })
}

/// Extract a nonassembly file without interpreting its Windows path.
fn file(node: Node<'_, '_>) -> Result<File, Error> {
    Ok(File {
        name: required_attribute(node, "name")?.into(),
        size: aliased_attribute(node, &[(None, "size"), (Some(ASM_V2), "size")])?
            .map(|value| parse_attribute_value(node, "size", &value))
            .transpose()?,
        group: attribute(node, "group"),
        optional: boolean_attribute(node, "optional")?,
        writeable_type: attribute(node, "writeableType"),
        hashes: children(node, "hash", ASSEMBLY_NAMESPACES)
            .map(hash)
            .collect::<Result<_, _>>()?,
    })
}

/// Extract an executable entry point or custom-host activation declaration.
fn entry_point(node: Node<'_, '_>) -> Result<EntryPoint, Error> {
    let identity = child(node, "assemblyIdentity", ASSEMBLY_NAMESPACES)?
        .map(identity)
        .transpose()?;
    let command_line = child(node, "commandLine", ASSEMBLY_NAMESPACES)?
        .map(|command| {
            Ok::<_, Error>(CommandLine {
                file: required_attribute(command, "file")?.into(),
                parameters: attribute(command, "parameters"),
            })
        })
        .transpose()?;
    let custom_host_required = child(node, "customHostRequired", ASSEMBLY_NAMESPACES)?.is_some();
    if custom_host_required && (identity.is_some() || command_line.is_some()) {
        return Err(Error::InvalidStructure(
            "customHostRequired excludes assemblyIdentity and commandLine".into(),
        ));
    }
    Ok(EntryPoint {
        name: attribute(node, "name"),
        identity,
        command_line,
        custom_host_required,
        custom_ux: child(node, "customUX", &[CLICKONCE_V1])?.is_some(),
    })
}
