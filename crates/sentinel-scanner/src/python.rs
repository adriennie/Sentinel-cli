//! Bounded, read-only Python lockfile inventory. Never invokes a package manager.
use crate::{Inventory, Package, ScanError, MAX_INPUT_BYTES};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct UvLock {
    version: u32,
    revision: Option<u32>,
    package: Vec<UvPackage>,
}

#[derive(Deserialize)]
struct UvPackage {
    name: String,
    version: Option<String>,
    source: BTreeMap<String, toml::Value>,
}

#[derive(Deserialize)]
struct PoetryLock {
    metadata: PoetryMetadata,
    package: Vec<PoetryPackage>,
}

#[derive(Deserialize)]
struct PoetryMetadata {
    #[serde(rename = "lock-version")]
    version: String,
}

#[derive(Deserialize)]
struct PoetryPackage {
    name: String,
    version: Option<String>,
    // Keep the source shape intact: malformed or unknown sources must never
    // deserialize as an absent source (which means default PyPI in Poetry).
    source: Option<toml::Value>,
}

pub(crate) fn parse_poetry(
    input: &[u8],
    file: &str,
    inventory: &mut Inventory,
) -> Result<(), ScanError> {
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(ScanError("Python lockfile exceeds size limit"));
    }
    let text = std::str::from_utf8(input).map_err(|_| ScanError("Python lockfile is not UTF-8"))?;
    let lock: PoetryLock =
        toml::from_str(text).map_err(|_| ScanError("Malformed Poetry lockfile"))?;
    if !matches!(lock.metadata.version.as_str(), "1.1" | "2.0" | "2.1") {
        return Err(ScanError("Unsupported Poetry lockfile schema version"));
    }
    for package in lock.package {
        let public = match package.source {
            None => true,
            Some(toml::Value::Table(source)) => {
                source
                    .keys()
                    .all(|key| matches!(key.as_str(), "type" | "url" | "reference"))
                    && source.get("type").and_then(toml::Value::as_str) == Some("legacy")
                    && matches!(
                        source.get("url").and_then(toml::Value::as_str),
                        Some("https://pypi.org/simple" | "https://pypi.org/simple/")
                    )
            }
            _ => false,
        };
        if !public {
            inventory.diagnostic_code(
                file,
                "python_source_uncovered",
                "Python private, local, Git, URL, or unknown source cannot be queried as public PyPI; provide a public resolved identity only when provenance is established",
            );
            continue;
        }
        match package.version {
            Some(version) => insert_python(package.name, version, file, inventory)?,
            None => inventory.diagnostic_code(file, "python_version_unresolved", "Python registry dependency has no exact version; regenerate its lockfile with the project package manager"),
        }
    }
    Ok(())
}

pub(crate) fn parse_uv(
    input: &[u8],
    file: &str,
    inventory: &mut Inventory,
) -> Result<(), ScanError> {
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(ScanError("Python lockfile exceeds size limit"));
    }
    let text = std::str::from_utf8(input).map_err(|_| ScanError("Python lockfile is not UTF-8"))?;
    let lock: UvLock = toml::from_str(text).map_err(|_| ScanError("Malformed uv lockfile"))?;
    if lock.version != 1 || lock.revision.is_some_and(|revision| revision > 5) {
        return Err(ScanError(
            "Unsupported uv lockfile schema version or revision",
        ));
    }
    for package in lock.package {
        let public = package.source.len() == 1
            && matches!(
                package.source.get("registry").and_then(toml::Value::as_str),
                Some("https://pypi.org/simple" | "https://pypi.org/simple/")
            );
        if !public {
            inventory.diagnostic_code(
                file,
                "python_source_uncovered",
                "Python private, local, Git, URL, or unknown source cannot be queried as public PyPI; provide a public resolved identity only when provenance is established",
            );
            continue;
        }
        let Some(version) = package.version else {
            inventory.diagnostic_code(file, "python_version_unresolved", "Python registry dependency has no exact version; regenerate its lockfile with the project package manager");
            continue;
        };
        insert_python(package.name, version, file, inventory)?;
    }
    Ok(())
}

fn insert_python(
    name: String,
    version: String,
    file: &str,
    inventory: &mut Inventory,
) -> Result<(), ScanError> {
    static VERSIONS: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
        std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r"(?ix)^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$",
            )
        });
    let versions = VERSIONS
        .as_ref()
        .map_err(|_| ScanError("Unable to initialize Python version validation"))?;
    // Preserve Python version spelling; Python versions are not Rust SemVer.
    // Validate the lexical identity before accepting it into the shared inventory.
    if !valid_name(&name) || !versions.is_match(&version) {
        inventory.diagnostic_code(file, "python_version_unresolved", "Python package name or exact version is invalid or unsupported; regenerate its lockfile without guessing a version");
        return Ok(());
    }
    let original_name = name;
    let mut name = String::new();
    for c in original_name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !name.ends_with('-') {
                name.push('-');
            }
        } else {
            name.push(c.to_ascii_lowercase());
        }
    }
    let identity = Package {
        ecosystem: "PyPI".into(),
        name,
        version,
    };
    if identity.validate().is_err() {
        inventory.diagnostic_code(file, "python_version_unresolved", "Python package name or exact version is invalid or unsupported; regenerate its lockfile without guessing a version");
        return Ok(());
    }
    inventory.insert(identity, file)?;
    Ok(())
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
}
