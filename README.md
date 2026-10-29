# clickonce

A Rust library for reading ClickOnce deployment manifests (`.application`) and
application manifests (`.exe.manifest`). It parses XML and exposes owned metadata;
it does not download, install, or launch applications.

```toml
[dependencies]
clickonce = { git = "https://github.com/cmeister2/clickonce" }
```

```rust
use clickonce::{Dependency, Manifest};

let manifest = Manifest::from_path("fixtures/MTGO.application")?;
println!("{}", manifest.identity.name);

if let Some(version) = manifest.identity.version {
    println!("Version: {version}, build {}", version.build);
}

for dependency in &manifest.dependencies {
    if let Dependency::Assembly(assembly) = dependency {
        println!("{}: {:?}", assembly.identity.name, assembly.codebase);
    }
}
# Ok::<(), clickonce::Error>(())
```

Run the included example with:

```sh
cargo run --example inspect -- fixtures/MTGO.application
```

## Types and supported metadata

The parser matches XML namespace URIs and local names, so prefix spelling does
not matter. It reads assembly identities, descriptions, deployment and update
settings, ordered framework requirements, assembly and OS dependencies, file
XMLDSIG digests, entry points, payload files, file associations, and publisher metadata.

Assembly versions contain four `u16` components. Framework/runtime versions
contain two to four components. Public-key tokens contain eight decoded bytes;
digest values contain validated, decoded base64 bytes. Processor architectures,
dependency kinds, update units, transforms, and digest algorithms use enums that
retain unrecognized values in `Other(String)`.

File sizes use `u64`, and OS version components use `u32`. Optional booleans
preserve the difference between an omitted value and an explicit `false`.
Codebases remain strings: the format permits URLs, UNC paths, and Windows-relative
paths, which should not acquire the host operating system's path semantics.

Unknown elements and attributes remain available through `manifest.xml()` and
the namespace-aware tree returned by `manifest.document()`. Source XML is
retained in full, including signatures, trust declarations, and COM metadata.
Typed values may normalize equivalent spellings when displayed or serialized;
the source retains their original spelling.
Legacy file `hash`/`hashalg` attributes are available through the source XML.

## Optional Serde support

Enable `serde` to derive `Serialize` and `Deserialize` for `Manifest` and its model
types. The feature is disabled by default; XML parsing does not require Serde.

```toml
clickonce = { git = "https://github.com/cmeister2/clickonce", features = ["serde"] }
serde_json = "1"
```

```rust
let manifest = clickonce::Manifest::from_path("fixtures/MTGO.application")?;
let json = serde_json::to_string_pretty(&manifest)?;
let metadata: clickonce::Manifest = serde_json::from_str(&json)?;
assert_eq!(metadata.identity, manifest.identity);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Versions, tokens, algorithm names, and base64 digests use strings in Serde formats.
Deserialization validates versions, tokens, and base64 syntax. Source XML and
parser limits are excluded from serialized metadata, so a deserialized snapshot's
`xml()` returns `None` and `document()` returns `Error::NoXmlSource`.
Serde support describes metadata; it does not deserialize ClickOnce XML directly
through an arbitrary Serde XML backend.

## Input handling and limits

Use `Manifest::parse` for an already decoded `&str`, `from_bytes` for bytes,
`from_reader` for a `Read` stream, or `from_path` for a local file. Byte input
supports UTF-8 and UTF-16 LE/BE, including BOM handling. Malformed Unicode,
unsupported encodings, and conflicting byte-encoding declarations are errors.
The retained XML is decoded text, not a byte-for-byte copy of UTF-16 input.

Defaults limit encoded input and decoded text to 16 MiB and the XML tree to
250,000 nodes. Streaming reads stop after the byte limit plus one byte. Customize
these limits for larger manifests:

```rust
let manifest = clickonce::ParseOptions {
    max_input_bytes: 64 * 1024 * 1024,
    max_nodes: 1_000_000,
}.from_reader(std::fs::File::open("large.application")?)?;
# Ok::<(), clickonce::Error>(())
```

The parser rejects DTD entity declarations and never resolves external entities.
It rejects malformed known values, essential missing identities/attributes,
duplicate singleton elements, and contradictory update/entry-point structures.
It does not perform complete XSD validation or verify signatures, certificates,
payload hashes, or whether Windows would accept a deployment. A signature's
presence is only reported as `has_signature`.

`.appref-ms` launch references are a separate text format and are outside this
crate's current scope.

## Development and release

MSRV: **Rust 1.85**; edition 2024. Run:

```sh
cargo test --locked
cargo test --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
```

CI checks stable and the MSRV on Linux, macOS, and Windows, verifies the declared
MSRV separately, and checks coverage and documentation. Local fixtures include
the supplied signed MTGO deployment and synthetic cases for application manifests,
namespaces, extensions, invalid values, Unicode, and resource limits.

Release tooling requires Node **24.15 or newer**. `npm ci && npm test` exercises
release-note generation through semantic-release's resolved dependencies and
the real Cargo plugin's preparation of both `Cargo.toml` and `Cargo.lock`.

Releases use
[`@semantic-release-cargo/semantic-release-cargo`](https://github.com/semantic-release-cargo/semantic-release-cargo)
for version preparation and crates.io publication. The checked-in version is
`0.0.0`; release versions are injected into the CI checkout. Tags use plain SemVer.
Only a manual run of **CI** with **release = true** on `main` or `master` can
publish. Ordinary pushes and pull requests run checks. Configure the repository's
`CARGO_REGISTRY_TOKEN` Actions secret before requesting a release.

Format references: Microsoft's [deployment manifest documentation](https://learn.microsoft.com/en-us/visualstudio/deployment/clickonce-deployment-manifest)
and [application manifest documentation](https://learn.microsoft.com/en-us/visualstudio/deployment/clickonce-application-manifest).
