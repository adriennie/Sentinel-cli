use crate::{bounded_read, Diagnostic, Package, ScanError, MAX_INPUT_BYTES, MAX_PACKAGES};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Default)]
pub struct Inventory {
    pub inputs: Vec<String>,
    pub packages: BTreeMap<Package, BTreeSet<String>>,
    pub diagnostics: Vec<Diagnostic>,
}
impl Inventory {
    fn diagnostic(&mut self, file: &str, message: &'static str) {
        self.diagnostics.push(Diagnostic {
            package: None,
            code: "unsupported_dependency",
            file: Some(file.into()),
            message,
        });
    }
    fn insert(&mut self, package: Package, file: &str) -> Result<(), ScanError> {
        package.validate()?;
        if self.packages.len() >= MAX_PACKAGES && !self.packages.contains_key(&package) {
            return Err(ScanError(
                "Dependency inventory exceeds 10,000 unique packages",
            ));
        }
        self.packages
            .entry(package)
            .or_default()
            .insert(file.into());
        Ok(())
    }
}
#[derive(Deserialize)]
struct CargoLock {
    version: Option<u32>,
    package: Vec<CargoPackage>,
}
#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    source: Option<String>,
}
pub fn parse_cargo(input: &[u8], file: &str, inventory: &mut Inventory) -> Result<(), ScanError> {
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(ScanError("Scan input exceeds size limit"));
    }
    let text = std::str::from_utf8(input).map_err(|_| ScanError("Cargo lockfile is not UTF-8"))?;
    let lock: CargoLock =
        toml::from_str(text).map_err(|_| ScanError("Malformed Cargo lockfile"))?;
    if !matches!(lock.version, None | Some(1..=4)) {
        return Err(ScanError("Unsupported Cargo lockfile version"));
    }
    for package in lock.package {
        match package.source.as_deref() {
            Some(
                "registry+https://github.com/rust-lang/crates.io-index"
                | "sparse+https://index.crates.io/",
            ) => inventory.insert(
                Package {
                    ecosystem: "crates.io".into(),
                    name: package.name,
                    version: package.version,
                },
                file,
            )?,
            None => {} // Workspace/local source; discovered nested lockfiles are scanned separately.
            _ => inventory.diagnostic(
                file,
                "Cargo git or alternate-registry dependency is not covered by crates.io lookup",
            ),
        }
    }
    Ok(())
}
pub fn parse_npm(input: &[u8], file: &str, inventory: &mut Inventory) -> Result<(), ScanError> {
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(ScanError("Scan input exceeds size limit"));
    }
    let lock: Value =
        serde_json::from_slice(input).map_err(|_| ScanError("Malformed npm lockfile"))?;
    if !matches!(
        lock.get("lockfileVersion").and_then(Value::as_u64),
        Some(2 | 3)
    ) {
        return Err(ScanError(
            "Only npm lockfile versions 2 and 3 are supported",
        ));
    }
    let packages = lock
        .get("packages")
        .and_then(Value::as_object)
        .ok_or(ScanError("npm lockfile is missing packages"))?;
    for (path, entry) in packages {
        let entry = entry
            .as_object()
            .ok_or(ScanError("Invalid npm package entry"))?;
        if path.is_empty() {
            continue;
        } // project itself
        if entry.get("link").and_then(Value::as_bool) == Some(true) {
            let represented = entry
                .get("resolved")
                .and_then(Value::as_str)
                .is_some_and(|target| {
                    !target.starts_with('/')
                        && !target.contains(['\\', ':'])
                        && !target.split('/').any(|part| part == "..")
                        && packages.contains_key(target)
                });
            if !represented {
                inventory.diagnostic(
                    file,
                    "npm linked dependency is not represented by a project-local lockfile entry",
                );
            }
            continue;
        } // workspaces are represented by their real entries
        if !path.contains("node_modules/") {
            continue;
        } // local workspace projects
        let version = entry
            .get("version")
            .and_then(Value::as_str)
            .ok_or(ScanError("npm package missing resolved version"))?;
        let resolved = entry.get("resolved").and_then(Value::as_str);
        if !version.as_bytes().first().is_some_and(u8::is_ascii_digit)
            || resolved.is_some_and(|url| !url.starts_with("https://registry.npmjs.org/"))
        {
            inventory.diagnostic(
                file,
                "npm git, local, or alternate-registry dependency is not covered by npm lookup",
            );
            continue;
        }
        let inferred = path
            .rsplit("node_modules/")
            .next()
            .ok_or(ScanError("Invalid npm package path"))?;
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(inferred);
        let registry_name = resolved
            .and_then(|url| url.strip_prefix("https://registry.npmjs.org/"))
            .and_then(|path| path.split_once("/-/").map(|(name, _)| name));
        let name = registry_name.unwrap_or(name);
        if name.contains('%') {
            inventory.diagnostic(
                file,
                "Encoded registry package names require additional identity handling",
            );
            continue;
        }
        inventory.insert(
            Package {
                ecosystem: "npm".into(),
                name: name.into(),
                version: version.into(),
            },
            file,
        )?;
    }
    Ok(())
}

pub fn parse_sbom(input: &[u8], file: &str, inventory: &mut Inventory) -> Result<(), ScanError> {
    if input.len() as u64 > MAX_INPUT_BYTES {
        return Err(ScanError("Scan input exceeds size limit"));
    }
    let bom: Value =
        serde_json::from_slice(input).map_err(|_| ScanError("Malformed CycloneDX JSON"))?;
    if bom.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX")
        || !matches!(
            bom.get("specVersion").and_then(Value::as_str),
            Some("1.4" | "1.5" | "1.6" | "1.7")
        )
    {
        return Err(ScanError(
            "Supported SBOM input is CycloneDX JSON 1.4 through 1.7",
        ));
    }
    let components = bom
        .get("components")
        .and_then(Value::as_array)
        .ok_or(ScanError("SBOM must contain components"))?;
    fn visit(
        components: &[Value],
        file: &str,
        inventory: &mut Inventory,
        depth: usize,
    ) -> Result<(), ScanError> {
        if depth > 32 {
            return Err(ScanError("SBOM nesting limit exceeded"));
        }
        for component in components {
            if let Some(children) = component.get("components").and_then(Value::as_array) {
                visit(children, file, inventory, depth + 1)?;
            }
            if let Some(purl) = component.get("purl").and_then(Value::as_str) {
                let purl = purl
                    .parse::<packageurl::PackageUrl>()
                    .map_err(|_| ScanError("Invalid SBOM package URL"))?;
                let ecosystem = match purl.ty() {
                    "cargo" => "crates.io",
                    "npm" => "npm",
                    "pypi" => "PyPI",
                    "maven" => "Maven",
                    "golang" => "Go",
                    "gem" => "RubyGems",
                    "nuget" => "NuGet",
                    "composer" => "Packagist",
                    "hex" => "Hex",
                    "pub" => "Pub",
                    _ => {
                        inventory.diagnostic(
                            file,
                            "SBOM package ecosystem is not supported by this scanner",
                        );
                        continue;
                    }
                };
                if !purl.qualifiers().is_empty() || purl.subpath().is_some() {
                    inventory.diagnostic(
                        file,
                        "Qualified or subpath package URLs require additional identity handling",
                    );
                    continue;
                }
                let Some(version) = purl.version() else {
                    inventory.diagnostic(file, "SBOM component has no exact version");
                    continue;
                };
                if component
                    .get("version")
                    .and_then(Value::as_str)
                    .is_some_and(|v| v != version)
                {
                    return Err(ScanError("SBOM version conflicts with package URL"));
                }
                let name = match purl.namespace() {
                    Some(namespace) => format!(
                        "{namespace}{}{name}",
                        if ecosystem == "Maven" { ":" } else { "/" },
                        name = purl.name()
                    ),
                    None => purl.name().to_string(),
                };
                inventory.insert(
                    Package {
                        ecosystem: ecosystem.into(),
                        name,
                        version: version.into(),
                    },
                    file,
                )?;
            } else {
                inventory.diagnostic(
                    file,
                    "SBOM component has no package URL; coverage unavailable",
                );
            }
        }
        Ok(())
    }
    visit(components, file, inventory, 0)
}

/// Walk monorepos with gitignore rules, without following symlinks or running tools.
pub fn discover(root: &Path, sbom: Option<&Path>) -> Inventory {
    let mut inventory = Inventory::default();
    if let Some(path) = sbom {
        inventory.inputs.push("<sbom>".into());
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            root.join(path)
        };
        let result = bounded_read(&path, MAX_INPUT_BYTES)
            .and_then(|bytes| parse_sbom(&bytes, "<sbom>", &mut inventory));
        if let Err(error) = result {
            inventory.diagnostic("<sbom>", error.0);
        }
        return inventory;
    }
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .hidden(false)
        .require_git(false)
        .follow_links(false)
        .max_depth(Some(64));
    builder.filter_entry(|entry| {
        !matches!(
            entry.file_name().to_str(),
            Some(
                ".git"
                    | ".sentinel"
                    | "node_modules"
                    | "target"
                    | "vendor"
                    | "dist"
                    | "build"
                    | ".venv"
                    | "venv"
            )
        )
    });
    let mut files = Vec::new();
    let mut markers = BTreeSet::new();
    let mut supported = BTreeSet::new();
    for (count, entry) in builder.build().enumerate() {
        if count >= 100_000 {
            inventory.diagnostic(".", "Discovery limit exceeded");
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                inventory.diagnostic(".", "Unable to inspect a project entry");
                continue;
            }
        };
        let Some(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if entry.depth() >= 64 {
                inventory.diagnostic(".", "Discovery depth limit reached");
            }
            continue;
        }
        let name = entry.file_name().to_str().unwrap_or("");
        let relative = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        if matches!(name, "Cargo.lock" | "package-lock.json") {
            if kind.is_symlink() {
                inventory.diagnostic(&relative, "Lockfile symlinks are not followed");
                continue;
            }
            supported.insert((
                entry.path().parent().map(Path::to_path_buf),
                if name == "Cargo.lock" { "cargo" } else { "npm" },
            ));
            files.push((entry.path().to_path_buf(), relative, name == "Cargo.lock"));
        } else if matches!(name, "Cargo.toml" | "package.json") {
            markers.insert((
                entry.path().parent().map(Path::to_path_buf),
                if name == "Cargo.toml" { "cargo" } else { "npm" },
            ));
        } else if matches!(
            name,
            "yarn.lock"
                | "pnpm-lock.yaml"
                | "bun.lock"
                | "bun.lockb"
                | "requirements.txt"
                | "poetry.lock"
                | "uv.lock"
                | "Pipfile.lock"
                | "pyproject.toml"
                | "pom.xml"
                | "build.gradle"
                | "build.gradle.kts"
                | "go.mod"
                | "go.sum"
                | "Gemfile.lock"
                | "composer.lock"
                | "packages.lock.json"
                | "pubspec.lock"
                | "mix.lock"
                | "Package.resolved"
                | "CMakeLists.txt"
                | "conan.lock"
                | "vcpkg.json"
        ) || name.ends_with(".csproj")
        {
            inventory.diagnostic(
                &relative,
                "Native parser unavailable; supply a CycloneDX JSON SBOM using --sbom",
            );
        }
    }
    files.sort_by(|a, b| a.1.cmp(&b.1));
    if files.len() > 256 {
        inventory.diagnostic(
            ".",
            "Lockfile limit exceeded; select a smaller project or provide --sbom",
        );
        files.truncate(256);
    }
    if files.is_empty() {
        inventory.diagnostic(".", "No supported dependency lockfiles discovered; supply a CycloneDX JSON SBOM with --sbom");
    }
    let mut npm_workspaces = BTreeSet::new();
    for (path, file, cargo) in files {
        inventory.inputs.push(file.clone());
        let result = bounded_read(&path, MAX_INPUT_BYTES).and_then(|bytes| {
            if cargo {
                parse_cargo(&bytes, &file, &mut inventory)
            } else {
                let result = parse_npm(&bytes, &file, &mut inventory);
                if let (Some(parent), Ok(value)) =
                    (path.parent(), serde_json::from_slice::<Value>(&bytes))
                {
                    if let Some(packages) = value.get("packages").and_then(Value::as_object) {
                        for key in packages.keys() {
                            if !key.is_empty()
                                && !key.contains("node_modules")
                                && !key.starts_with('/')
                                && !key.contains(['\\', ':'])
                                && !key.split('/').any(|part| part == "..")
                            {
                                npm_workspaces.insert(parent.join(key));
                            }
                        }
                    }
                }
                result
            }
        });
        if let Err(error) = result {
            inventory.diagnostic(&file, error.0);
        }
    }
    for (directory, ecosystem) in markers.difference(&supported) {
        // Cargo workspace members may share an ancestor Cargo.lock.
        let covered = (*ecosystem == "npm"
            && directory
                .as_ref()
                .is_some_and(|dir| npm_workspaces.contains(dir)))
            || *ecosystem == "cargo"
                && supported.iter().any(|(parent, kind)| {
                    *kind == "cargo"
                        && directory
                            .as_ref()
                            .zip(parent.as_ref())
                            .is_some_and(|(dir, parent)| dir.starts_with(parent))
                });
        if !covered {
            inventory.diagnostic(".", "Project manifest has no supported resolved lockfile; generate a lockfile or provide --sbom");
        }
    }
    inventory
}
