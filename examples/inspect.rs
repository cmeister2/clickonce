//! Print the identity and dependency codebases declared in a local manifest.

use clickonce::{Dependency, Manifest};

/// Read a manifest path from the command line and print its typed metadata.
///
/// # Errors
/// Returns an error when the argument is absent or the file cannot be parsed.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: cargo run --example inspect -- <manifest.application>")?;
    let manifest = Manifest::from_path(path)?;
    println!("Name: {}", manifest.identity.name);
    if let Some(version) = manifest.identity.version {
        println!("Version: {version}");
    }
    if let Some(publisher) = manifest
        .description
        .as_ref()
        .and_then(|description| description.publisher.as_ref())
    {
        println!("Publisher: {publisher}");
    }
    for dependency in &manifest.dependencies {
        if let Dependency::Assembly(assembly) = dependency {
            println!(
                "Dependency: {} ({})",
                assembly.identity.name,
                assembly.codebase.as_deref().unwrap_or("prerequisite")
            );
        }
    }
    Ok(())
}
