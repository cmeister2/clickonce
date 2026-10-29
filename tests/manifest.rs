//! Behavioral tests for ClickOnce XML parsing and input boundaries.

use std::io::{self, Cursor, Read};

use clickonce::{
    Dependency, DigestAlgorithm, Error, HashTransform, Manifest, ManifestKind, ParseOptions,
    ProcessorArchitecture, UpdatePolicy, UpdateUnit,
};

/// A namespace-complete assembly wrapper for small synthetic manifests.
fn assembly(contents: &str) -> String {
    format!(
        r#"<a:assembly xmlns:a="urn:schemas-microsoft-com:asm.v1"
          xmlns:d="urn:schemas-microsoft-com:asm.v2"
          xmlns:c="urn:schemas-microsoft-com:clickonce.v1"
          xmlns:f="urn:schemas-microsoft-com:clickonce.v2"
          xmlns:s="http://www.w3.org/2000/09/xmldsig#"
          xmlns:x="urn:example:extension" manifestVersion="1.0">
          <a:assemblyIdentity name="Example.application" version="1.2.3.4" />
          {contents}
        </a:assembly>"#
    )
}

/// The supplied signed deployment exercises real mixed namespaces and paths.
#[test]
fn supplied_mtgo_deployment() {
    let manifest = Manifest::from_bytes(include_bytes!("../fixtures/MTGO.application")).unwrap();
    assert_eq!(manifest.kind, ManifestKind::Deployment);
    assert_eq!(manifest.manifest_version, "1.0");
    assert_eq!(manifest.identity.name, "MTGO.application");
    assert_eq!(
        manifest.identity.version,
        Some("3.4.159.4708".parse().unwrap())
    );
    assert_eq!(
        manifest.identity.processor_architecture,
        Some(ProcessorArchitecture::Msil)
    );
    let description = manifest.description.as_ref().unwrap();
    assert_eq!(
        description.publisher.as_deref(),
        Some("Daybreak Game Company LLC")
    );
    assert_eq!(
        description.product.as_deref(),
        Some("Magic The Gathering Online ")
    );
    let deployment = manifest.deployment.as_ref().unwrap();
    assert_eq!(deployment.install, Some(true));
    assert_eq!(deployment.create_desktop_shortcut, Some(true));
    assert_eq!(
        deployment.update,
        Some(UpdatePolicy::BeforeApplicationStartup)
    );
    assert_eq!(manifest.frameworks.len(), 2);
    assert_eq!(manifest.frameworks[0].target_version.to_string(), "4.7.2");
    assert_eq!(manifest.frameworks[0].profile.as_deref(), Some("Client"));
    assert_eq!(manifest.frameworks[1].profile.as_deref(), Some("Full"));
    let Dependency::Assembly(dependency) = &manifest.dependencies[0] else {
        panic!("MTGO must reference its application manifest");
    };
    assert_eq!(
        dependency.codebase.as_deref(),
        Some(r"3.4.159.4708.20261014120111\MTGO.exe.manifest")
    );
    assert_eq!(dependency.size, Some(469_108));
    let hash = dependency.hashes.first().unwrap();
    assert_eq!(hash.digest_method, DigestAlgorithm::Sha256);
    assert_eq!(
        hash.digest_value.to_string(),
        "MqMtNWJ7oGAiPdyevvnv96THB2i7YRf0BOSut+RKz38="
    );
    assert!(manifest.has_signature);
    assert!(manifest.publisher_identity.is_some());
    assert!(
        manifest
            .document()
            .unwrap()
            .root_element()
            .has_tag_name(("urn:schemas-microsoft-com:asm.v1", "assembly"))
    );
}

/// Namespace aliases and declaration order do not determine element identity.
#[test]
fn alternate_prefixes_have_identical_metadata() {
    let xml = assembly(
        r#"<a:description d:publisher="Example &amp; Company" d:product="Demo" />
           <d:deployment install="1" c:createDesktopShortcut="0" />"#,
    );
    let renamed = xml
        .replace("a:", "assembly:")
        .replace("xmlns:a=", "xmlns:assembly=")
        .replace("d:", "deployment:")
        .replace("xmlns:d=", "xmlns:deployment=")
        .replace("c:", "clickonce:")
        .replace("xmlns:c=", "xmlns:clickonce=");
    let original = Manifest::parse(&xml).unwrap();
    let alternate = Manifest::parse(&renamed).unwrap();
    assert_eq!(original.identity, alternate.identity);
    assert_eq!(original.description, alternate.description);
    assert_eq!(original.deployment, alternate.deployment);
    assert_eq!(
        original.deployment.unwrap().create_desktop_shortcut,
        Some(false)
    );
}

/// Foreign elements and attributes cannot replace recognized metadata.
#[test]
fn foreign_namespaces_do_not_hijack_fields() {
    let xml = assembly(
        r#"<x:assemblyIdentity name="Spoof" />
           <x:deployment install="definitely-invalid" />
           <a:description x:publisher="Spoof" d:publisher="Real" />
           <d:deployment x:install="definitely-invalid" />
           <x:Signature />"#,
    );
    let manifest = Manifest::parse(&xml).unwrap();
    assert_eq!(manifest.identity.name, "Example.application");
    assert_eq!(
        manifest.description.as_ref().unwrap().publisher.as_deref(),
        Some("Real")
    );
    assert_eq!(manifest.deployment.as_ref().unwrap().install, None);
    assert!(!manifest.has_signature);
    assert_eq!(manifest.xml(), Some(xml.as_str()));
}

/// Legacy manifests may omit newer framework and deployment declarations.
#[test]
fn optional_settings_stay_absent() {
    let manifest = Manifest::parse(&assembly("")).unwrap();
    assert_eq!(manifest.kind, ManifestKind::Assembly);
    assert!(manifest.description.is_none());
    assert!(manifest.deployment.is_none());
    assert!(manifest.frameworks.is_empty());
    assert!(manifest.dependencies.is_empty());
    let manifest = Manifest::parse(&assembly("<d:deployment />")).unwrap();
    let deployment = manifest.deployment.unwrap();
    assert!(deployment.provider.is_none());
    assert!(deployment.update.is_none());
    assert!(deployment.install.is_none());
}

/// Repeated dependencies retain document order even when interleaved.
#[test]
fn interleaved_dependencies_and_windows_codebases() {
    let manifest = Manifest::parse(&assembly(
        r#"<d:dependency><d:dependentAssembly dependencyType="preRequisite">
             <d:assemblyIdentity name="Runtime" />
           </d:dependentAssembly></d:dependency>
           <a:description d:product="Demo" />
           <d:dependency><d:dependentAssembly dependencyType="install"
               codebase="\\server\release\Demo.exe.manifest" size="4294967296">
             <d:assemblyIdentity name="Demo" processorArchitecture="arm64" />
           </d:dependentAssembly></d:dependency>"#,
    ))
    .unwrap();
    let names: Vec<_> = manifest
        .dependencies
        .iter()
        .map(|dependency| {
            let Dependency::Assembly(assembly) = dependency else {
                panic!("expected assembly dependency");
            };
            assembly.identity.name.as_str()
        })
        .collect();
    assert_eq!(names, ["Runtime", "Demo"]);
    let Dependency::Assembly(dependency) = &manifest.dependencies[1] else {
        panic!("expected application manifest dependency");
    };
    assert_eq!(dependency.size, Some(4_294_967_296));
    assert_eq!(
        dependency.codebase.as_deref(),
        Some(r"\\server\release\Demo.exe.manifest")
    );
    assert_eq!(
        dependency.identity.processor_architecture,
        Some(ProcessorArchitecture::Arm64)
    );
    assert!(dependency.hashes.is_empty());
}

/// Application manifests expose executable, payload, and OS requirement metadata.
#[test]
fn application_manifest() {
    let manifest = Manifest::parse(&assembly(
        r#"<d:application />
           <d:entryPoint name="Main">
             <d:assemblyIdentity name="Demo.exe" />
             <d:commandLine file="Demo.exe" parameters="&quot;two words&quot; %TEMP%" />
             <c:customUX />
           </d:entryPoint>
           <d:dependency><d:dependentOS supportUrl="https://example.org/windows">
             <d:osVersionInfo><d:os majorVersion="10" minorVersion="0"
               buildNumber="19045" servicePackMajor="0" /></d:osVersionInfo>
           </d:dependentOS></d:dependency>
           <d:file name="data\cards.bin" size="12" optional="false" writeableType="applicationData">
             <d:hash><s:Transforms><s:Transform Algorithm="urn:example:identity" />
               <s:Transform Algorithm="urn:example:second" /></s:Transforms>
               <s:DigestMethod Algorithm="urn:example:digest" />
               <s:DigestValue>YWJj</s:DigestValue></d:hash>
           </d:file>
           <c:fileAssociation extension=".demo" progid="Demo.Document" defaultIcon="Demo.ico" />"#,
    ))
    .unwrap();
    assert_eq!(manifest.kind, ManifestKind::Application);
    let entry = manifest.entry_point.unwrap();
    assert!(entry.custom_ux);
    assert!(!entry.custom_host_required);
    let command = entry.command_line.unwrap();
    assert_eq!(command.file, "Demo.exe");
    assert_eq!(command.parameters.as_deref(), Some("\"two words\" %TEMP%"));
    let Dependency::OperatingSystem(os) = &manifest.dependencies[0] else {
        panic!("expected operating system requirement");
    };
    assert_eq!(os.major_version, Some(10));
    assert_eq!(os.build_number, Some(19045));
    let file = &manifest.files[0];
    assert_eq!(file.name, r"data\cards.bin");
    assert_eq!(file.optional, Some(false));
    assert_eq!(
        file.hashes.first().unwrap().transforms,
        [
            HashTransform::Other("urn:example:identity".into()),
            HashTransform::Other("urn:example:second".into()),
        ]
    );
    assert_eq!(manifest.file_associations[0].extension, ".demo");
}

/// Background update intervals and framework support URLs preserve schema casing.
#[test]
fn background_updates_and_framework_support() {
    let manifest = Manifest::parse(&assembly(
        r#"<d:deployment trustURLParameters="true">
             <d:subscription><d:update><d:expiration maximumAge="6" unit="hours" />
             </d:update></d:subscription>
           </d:deployment>
           <f:compatibleFrameworks SupportUrl="https://example.org/runtime">
             <f:framework targetVersion="4.8" profile="Full" supportedRuntime="4.0.30319" />
           </f:compatibleFrameworks>"#,
    ))
    .unwrap();
    let deployment = manifest.deployment.unwrap();
    assert_eq!(
        deployment.update,
        Some(UpdatePolicy::Background {
            maximum_age: 6,
            unit: UpdateUnit::Hours
        })
    );
    assert_eq!(deployment.trust_url_parameters, Some(true));
    assert_eq!(
        manifest.frameworks_support_url.as_deref(),
        Some("https://example.org/runtime")
    );
}

/// Recognized booleans and unsigned integers reject invalid lexical values.
#[test]
fn invalid_typed_attributes() {
    for contents in [
        r#"<d:deployment install="True" />"#,
        r#"<d:file name="data" size="-1" />"#,
        r#"<d:file name="data" size="18446744073709551616" />"#,
    ] {
        assert!(matches!(
            Manifest::parse(&assembly(contents)),
            Err(Error::InvalidAttribute { .. })
        ));
    }
}

/// Namespace-spoofed roots and malformed documents cannot pass XML parsing.
#[test]
fn invalid_xml_and_root() {
    assert!(matches!(Manifest::parse("<assembly>"), Err(Error::Xml(_))));
    assert!(matches!(
        Manifest::parse(r#"<assembly xmlns="urn:example:foreign" />"#),
        Err(Error::InvalidRoot)
    ));
    assert!(matches!(
        Manifest::parse("<assembly />"),
        Err(Error::InvalidRoot)
    ));
}

/// Duplicate recognized singletons are reported rather than silently discarded.
#[test]
fn duplicate_singleton() {
    let xml = assembly("<d:deployment /><d:deployment />");
    assert!(matches!(
        Manifest::parse(&xml),
        Err(Error::DuplicateElement { .. })
    ));
}

/// External entity declarations are rejected before resolution can occur.
#[test]
fn external_entities_are_not_resolved() {
    let xml = format!(
        "<!DOCTYPE assembly [<!ENTITY external SYSTEM 'file:///should-never-be-read'>]>{}",
        assembly("<a:description>&external;</a:description>")
    );
    assert!(matches!(
        Manifest::parse(&xml),
        Err(Error::Xml(roxmltree::Error::DtdDetected))
    ));
}

/// A reader that records how many bytes the parser requests.
struct CountingReader {
    /// The input bytes and current read position.
    input: Cursor<Vec<u8>>,
    /// The total bytes returned to the caller.
    consumed: usize,
}

impl Read for CountingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.input.read(buffer)?;
        self.consumed += count;
        Ok(count)
    }
}

/// Both in-memory and streaming inputs obey configured byte and node limits.
#[test]
fn input_and_node_limits() {
    let xml = assembly("");
    let limit = xml.len() - 1;
    let options = ParseOptions {
        max_input_bytes: limit,
        ..ParseOptions::default()
    };
    assert!(
        matches!(options.parse(&xml), Err(Error::InputTooLarge { limit: actual }) if actual == limit)
    );
    let mut reader = CountingReader {
        input: Cursor::new(xml.into_bytes()),
        consumed: 0,
    };
    assert!(matches!(
        options.from_reader(&mut reader),
        Err(Error::InputTooLarge { .. })
    ));
    assert_eq!(reader.consumed, limit + 1);
    let options = ParseOptions {
        max_nodes: 1,
        ..ParseOptions::default()
    };
    assert!(matches!(
        options.parse(&assembly("")),
        Err(Error::Xml(roxmltree::Error::NodesLimitReached))
    ));
}

/// Decoded UTF-16 size is checked independently of its smaller encoded bytes.
#[test]
fn decoded_size_limit() {
    let xml = assembly(&format!(
        "<a:description>{}</a:description>",
        "ࠀ".repeat(2048)
    ));
    let mut bytes = vec![0xff, 0xfe];
    for unit in xml.encode_utf16() {
        bytes.extend(unit.to_le_bytes());
    }
    assert!(bytes.len() < xml.len());
    let options = ParseOptions {
        max_input_bytes: bytes.len(),
        ..ParseOptions::default()
    };
    assert!(matches!(
        options.from_bytes(&bytes),
        Err(Error::InputTooLarge { .. })
    ));
}

/// File and reader conveniences share the same real-fixture behavior.
#[test]
fn reader_and_path_entry_points() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/MTGO.application");
    let from_path = Manifest::from_path(path).unwrap();
    let from_reader =
        Manifest::from_reader(include_bytes!("../fixtures/MTGO.application").as_slice()).unwrap();
    assert_eq!(from_path.identity, from_reader.identity);
    assert_eq!(from_path.dependencies, from_reader.dependencies);
}

/// Legacy file sizes may use the assembly-v2 attribute namespace.
#[test]
fn namespaced_file_size_preserves_namespace_boundaries() {
    let manifest = Manifest::parse(&assembly(
        r#"<a:file name="Data.xml" d:size="39500" x:size="ignored" />"#,
    ))
    .unwrap();
    assert_eq!(manifest.files[0].size, Some(39_500));

    let manifest =
        Manifest::parse(&assembly(r#"<a:file name="Data.xml" x:size="39500" />"#)).unwrap();
    assert_eq!(manifest.files[0].size, None);

    assert!(matches!(
        Manifest::parse(&assembly(
            r#"<a:file name="Data.xml" size="39500" d:size="39500" />"#,
        )),
        Err(Error::InvalidStructure(_))
    ));
    assert!(matches!(
        Manifest::parse(&assembly(r#"<a:file name="Data.xml" d:size="invalid" />"#,)),
        Err(Error::InvalidAttribute { .. })
    ));
}

/// Dependencies and files can declare multiple digest algorithms in order.
#[test]
fn multiple_hashes_preserve_declaration_order() {
    let hashes = r#"<d:hash>
        <s:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
        <s:DigestValue>Zmlyc3Q=</s:DigestValue>
      </d:hash>
      <d:hash>
        <s:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
        <s:DigestValue>c2Vjb25k</s:DigestValue>
      </d:hash>"#;
    let manifest = Manifest::parse(&assembly(&format!(
        r#"<d:dependency><d:dependentAssembly dependencyType="install">
          <d:assemblyIdentity name="Demo.exe" />{hashes}
        </d:dependentAssembly></d:dependency>
        <d:file name="Data.xml">{hashes}</d:file>"#,
    )))
    .unwrap();
    let Dependency::Assembly(dependency) = &manifest.dependencies[0] else {
        panic!("expected assembly dependency");
    };
    for hashes in [&dependency.hashes, &manifest.files[0].hashes] {
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0].digest_method, DigestAlgorithm::Sha1);
        assert_eq!(hashes[0].digest_value.as_bytes(), b"first");
        assert_eq!(hashes[1].digest_method, DigestAlgorithm::Sha256);
        assert_eq!(hashes[1].digest_value.as_bytes(), b"second");
    }
}

/// Numeric attributes apply XML Schema whitespace handling without loosening tokens.
#[test]
fn numeric_attributes_accept_only_xml_whitespace() {
    let manifest = Manifest::parse(&assembly(
        r#"<d:file name="Data.xml" size=" &#x9;12&#xD;&#xA; " />
        <a:file name="Legacy.xml" d:size=" &#x9;34&#xD;&#xA; " />
        <d:dependency><d:dependentAssembly size=" 56 ">
          <d:assemblyIdentity name="Demo.exe" />
        </d:dependentAssembly></d:dependency>
        <d:dependency><d:dependentOS><d:osVersionInfo>
          <d:os majorVersion=" 10 " minorVersion=" 0 " buildNumber=" 19045 "
            servicePackMajor=" 1 " servicePackMinor=" 2 " />
        </d:osVersionInfo></d:dependentOS></d:dependency>
        <d:deployment><d:subscription><d:update>
          <d:expiration maximumAge=" 6 " unit="hours" />
        </d:update></d:subscription></d:deployment>"#,
    ))
    .unwrap();
    assert_eq!(manifest.files[0].size, Some(12));
    assert_eq!(manifest.files[1].size, Some(34));
    let Dependency::Assembly(dependency) = &manifest.dependencies[0] else {
        panic!("expected assembly dependency");
    };
    assert_eq!(dependency.size, Some(56));
    let Dependency::OperatingSystem(os) = &manifest.dependencies[1] else {
        panic!("expected operating system dependency");
    };
    assert_eq!(os.major_version, Some(10));
    assert_eq!(os.minor_version, Some(0));
    assert_eq!(os.build_number, Some(19045));
    assert_eq!(os.service_pack_major, Some(1));
    assert_eq!(os.service_pack_minor, Some(2));
    assert_eq!(
        manifest.deployment.unwrap().update,
        Some(UpdatePolicy::Background {
            maximum_age: 6,
            unit: UpdateUnit::Hours,
        })
    );
    for contents in [
        r#"<d:file name="Data.xml" size="&#xA0;12" />"#,
        r#"<d:dependency><d:dependentAssembly>
          <d:assemblyIdentity name="Demo.exe" version=" 1.2.3.4 " />
        </d:dependentAssembly></d:dependency>"#,
        r#"<d:dependency><d:dependentAssembly>
          <d:assemblyIdentity name="Demo.exe" publicKeyToken=" a2d3b1cd60f98833 " />
        </d:dependentAssembly></d:dependency>"#,
    ] {
        assert!(matches!(
            Manifest::parse(&assembly(contents)),
            Err(Error::InvalidAttribute { .. })
        ));
    }
}
