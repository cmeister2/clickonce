//! Optional serialization exposes metadata without pretending to serialize XML.

#![cfg(feature = "serde")]

use clickonce::{
    Dependency, DependencyType, DigestAlgorithm, Error, Manifest, ProcessorArchitecture,
};

/// JSON roundtrips preserve declared metadata while omitting the source document.
#[test]
fn metadata_roundtrip_omits_xml_source() {
    let manifest = Manifest::from_bytes(include_bytes!("../fixtures/MTGO.application")).unwrap();
    let json = serde_json::to_value(&manifest).unwrap();
    assert_eq!(json["identity"]["name"], "MTGO.application");
    assert!(!json.as_object().unwrap().contains_key("source"));
    assert!(!json.to_string().contains("StrongNameSignature"));
    let restored: Manifest = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(restored.identity, manifest.identity);
    assert_eq!(restored.deployment, manifest.deployment);
    assert_eq!(restored.dependencies, manifest.dependencies);
    assert_eq!(serde_json::to_value(&restored).unwrap(), json);
    assert!(restored.xml().is_none());
    assert!(matches!(restored.document(), Err(Error::NoXmlSource)));
}

/// New architecture labels and hash algorithm URIs survive parsing and JSON.
#[test]
fn extensible_strings_survive_serialization() {
    let xml = r#"<a:assembly xmlns:a="urn:schemas-microsoft-com:asm.v1"
        xmlns:d="urn:schemas-microsoft-com:asm.v2"
        xmlns:s="http://www.w3.org/2000/09/xmldsig#" manifestVersion="1.0">
        <a:assemblyIdentity name="Future.application" processorArchitecture="future64" />
        <d:dependency><d:dependentAssembly dependencyType="futureRelationship">
          <d:assemblyIdentity name="Future.exe" />
          <d:hash><s:DigestMethod Algorithm="urn:example:futureDigest" />
            <s:DigestValue>YWJj</s:DigestValue></d:hash>
        </d:dependentAssembly></d:dependency>
    </a:assembly>"#;
    let manifest = Manifest::parse(xml).unwrap();
    let restored: Manifest =
        serde_json::from_str(&serde_json::to_string(&manifest).unwrap()).unwrap();
    assert_eq!(
        restored.identity.processor_architecture,
        Some(ProcessorArchitecture::Other("future64".into()))
    );
    let Dependency::Assembly(dependency) = &restored.dependencies[0] else {
        panic!("expected assembly dependency");
    };
    assert_eq!(
        dependency.dependency_type,
        Some(DependencyType::Other("futureRelationship".into()))
    );
    assert_eq!(
        dependency.hashes.first().unwrap().digest_method,
        DigestAlgorithm::Other("urn:example:futureDigest".into())
    );
}
