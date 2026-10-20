//! Manifest/lock association is inventory evidence, not a freshness assertion.
use crate::{bounded_read, Inventory, Package, MAX_INPUT_BYTES};
use pep508_rs::{pep440_rs::Operator, Requirement, VerbatimUrl, VersionOrUrl};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub(crate) struct Projects {
    manifests: BTreeMap<PathBuf, toml::Value>,
    owners: BTreeMap<PathBuf, PathBuf>,
}
impl Projects {
    pub(crate) fn load(
        root: &Path,
        paths: &[PathBuf],
        locks: &BTreeSet<PathBuf>,
        inventory: &mut Inventory,
    ) -> Self {
        let mut result = Self {
            manifests: BTreeMap::new(),
            owners: BTreeMap::new(),
        };
        let mut total_bytes = 0usize;
        for path in paths.iter().take(256) {
            let file = label(root, path);
            let value = bounded_read(path, MAX_INPUT_BYTES.min(1024 * 1024))
                .ok()
                .and_then(|b| {
                    total_bytes = total_bytes.saturating_add(b.len());
                    if total_bytes > 16 * 1024 * 1024 {
                        None
                    } else {
                        String::from_utf8(b).ok()
                    }
                })
                .and_then(|s| s.parse::<toml::Value>().ok());
            if let Some(value) = value {
                result.manifests.insert(path.clone(), value);
            } else {
                inventory.diagnostic_code(
                    &file,
                    "python_manifest_unresolved",
                    "Python manifest is malformed, unreadable, or exceeds limits",
                );
            }
        }
        if paths.len() > 256 {
            inventory.diagnostic_code(
                ".",
                "python_manifest_unresolved",
                "Python manifest discovery exceeds 256 files",
            );
        }
        let mut workspaces = Vec::new();
        for (path, value) in &result.manifests {
            let Some(parent) = path.parent() else {
                continue;
            };
            if !locks.contains(parent) {
                continue;
            }
            if let Some(table) = value
                .get("tool")
                .and_then(|v| v.get("uv"))
                .and_then(|v| v.get("workspace"))
            {
                let compiled = if table.is_table() {
                    compile_patterns(table.get("members"))
                        .and_then(|m| compile_patterns(table.get("exclude")).map(|e| (m, e)))
                } else {
                    Err(())
                };
                match compiled {
                    Ok((members, exclude)) => {
                        workspaces.push((parent.to_path_buf(), members, exclude))
                    }
                    Err(()) => inventory.diagnostic_code(
                        &label(root, path),
                        "python_manifest_unresolved",
                        "Workspace patterns are malformed, unsafe, or exceed bounds",
                    ),
                }
            }
        }
        for (path, value) in &result.manifests {
            let Some(directory) = path.parent() else {
                continue;
            };
            if locks.contains(directory) {
                result.owners.insert(path.clone(), directory.into());
                continue;
            }
            let mut owners = Vec::new();
            for (parent, members, exclude) in &workspaces {
                if parent == directory {
                    continue;
                }
                if let Ok(relative) = directory.strip_prefix(parent) {
                    if members.is_match(relative) && !exclude.is_match(relative) {
                        owners.push(parent.clone());
                    }
                }
            }
            if owners.len() == 1 {
                result.owners.insert(path.clone(), owners.remove(0));
            } else if owners.len() > 1 {
                inventory.diagnostic_code(
                    &label(root, path),
                    "python_lock_conflict",
                    "Python manifest belongs to multiple lockfile workspaces",
                );
            }
            // A manifest that only configures tools is not a Python dependency declaration.
            if owners.is_empty()
                && !result.owners.contains_key(path)
                && value.get("project").is_none()
                && value.get("tool").and_then(|v| v.get("poetry")).is_none()
            {
                continue;
            }
        }
        result
    }
    pub(crate) fn local_member(&self, directory: &Path, source: &str, name: &str) -> bool {
        if !safe_path(source) && source != "." {
            return false;
        }
        let path = directory.join(source).join("pyproject.toml");
        self.manifests.iter().any(|(manifest, value)| {
            let relative = manifest
                .parent()
                .and_then(|p| p.strip_prefix(directory).ok())
                .map(|p| p.to_string_lossy().replace('\\', "/"));
            let expected = if source == "." {
                ""
            } else {
                source.trim_end_matches('/')
            };
            (manifest == &path || relative.as_deref() == Some(expected))
                && self
                    .owners
                    .get(manifest)
                    .is_some_and(|owner| owner == directory)
                && project_name(value).is_some_and(|n| normalized(n) == normalized(name))
        })
    }
    pub(crate) fn reconcile(&self, root: &Path, inventory: &mut Inventory) {
        for (path, value) in &self.manifests {
            let file = label(root, path);
            inventory.inputs.push(file.clone());
            let owned = self.owners.get(path);
            if value.get("project").is_some_and(|p| {
                !p.is_table()
                    || !p
                        .get("name")
                        .and_then(toml::Value::as_str)
                        .is_some_and(|n| n.parse::<pep508_rs::PackageName>().is_ok())
            }) {
                inventory.diagnostic_code(
                    &file,
                    "python_manifest_unresolved",
                    "Python project metadata needs a valid project name and table",
                );
                continue;
            }
            let mut declarations = Vec::new();
            if let Some(project) = value.get("project") {
                if project
                    .get("dynamic")
                    .and_then(toml::Value::as_array)
                    .is_some_and(|a| {
                        a.iter().any(|v| {
                            matches!(v.as_str(), Some("dependencies" | "optional-dependencies"))
                        })
                    })
                {
                    inventory.diagnostic_code(&file,"python_manifest_unresolved","Dynamic Python dependencies cannot be inspected without executing project code");
                }
                strings(
                    project.get("dependencies"),
                    &mut declarations,
                    &file,
                    inventory,
                );
                if let Some(groups) = project.get("optional-dependencies") {
                    if let Some(table) = groups.as_table() {
                        for group in table.values() {
                            strings(Some(group), &mut declarations, &file, inventory);
                        }
                    } else {
                        inventory.diagnostic_code(
                            &file,
                            "python_manifest_unresolved",
                            "Python optional dependency groups must be tables",
                        );
                    }
                }
            }
            if let Some(groups) = value.get("dependency-groups") {
                if let Some(table) = groups.as_table() {
                    for name in table.keys() {
                        if !group_valid(name, table, &mut BTreeSet::new(), &mut BTreeSet::new()) {
                            inventory.diagnostic_code(&file,"python_manifest_unresolved","Python dependency groups contain a cycle, missing group, or excessive nesting");
                            break;
                        }
                    }
                    for group in table.values() {
                        if let Some(array) = group.as_array() {
                            for entry in array {
                                if let Some(text) = entry.as_str() {
                                    declarations.push(text.to_owned());
                                } else if !entry.as_table().is_some_and(|t| {
                                    t.len() == 1
                                        && t.get("include-group")
                                            .and_then(toml::Value::as_str)
                                            .is_some_and(|s| table.contains_key(s))
                                }) {
                                    inventory.diagnostic_code(
                                        &file,
                                        "python_manifest_unresolved",
                                        "Python dependency-group include is malformed or missing",
                                    );
                                }
                            }
                        } else {
                            inventory.diagnostic_code(
                                &file,
                                "python_manifest_unresolved",
                                "Python dependency group must be an array",
                            );
                        }
                    }
                } else {
                    inventory.diagnostic_code(
                        &file,
                        "python_manifest_unresolved",
                        "Python dependency groups must be a table",
                    );
                }
            }
            let poetry = value.get("tool").and_then(|v| v.get("poetry"));
            if let Some(poetry) = poetry {
                for table in [poetry.get("dependencies"), poetry.get("dev-dependencies")]
                    .into_iter()
                    .flatten()
                {
                    poetry_declarations(table, &mut declarations, &file, inventory);
                }
                if let Some(groups) = poetry.get("group").and_then(toml::Value::as_table) {
                    for group in groups.values() {
                        if let Some(table) = group.get("dependencies") {
                            poetry_declarations(table, &mut declarations, &file, inventory);
                        }
                    }
                }
            }
            let uv = value.get("tool").and_then(|v| v.get("uv"));
            let mut has_source_overrides = poetry.and_then(|v| v.get("source")).is_some();
            if let Some(sources) = uv.and_then(|v| v.get("sources")) {
                has_source_overrides |= !sources.as_table().is_some_and(|table| {
                    table.iter().all(|(name, source)| {
                        source.as_table().is_some_and(|t| {
                            t.len() == 1
                                && t.get("workspace").and_then(toml::Value::as_bool) == Some(true)
                        }) && owned.is_some_and(|owner| {
                            self.manifests.iter().any(|(m, v)| {
                                self.owners.get(m) == Some(owner)
                                    && project_name(v)
                                        .is_some_and(|n| normalized(n) == normalized(name))
                            })
                        })
                    })
                });
            }
            has_source_overrides |= uv.is_some_and(|v| {
                ["index", "default-index", "index-url", "extra-index-url"]
                    .iter()
                    .any(|k| v.get(k).is_some())
            });
            if has_source_overrides {
                inventory.diagnostic_code(&file,"python_source_uncovered","Python manifest configures custom or unsupported dependency sources; known public lockfile identities are retained but source reconciliation is incomplete");
            }
            if declarations.len() > 10000 {
                inventory.diagnostic_code(
                    &file,
                    "python_manifest_unresolved",
                    "Python declaration count exceeds 10000 per manifest",
                );
                continue;
            }
            if owned.is_none() && (value.get("project").is_some() || poetry.is_some()) {
                inventory.diagnostic_code(&file,"python_inventory_partial","Python manifest has no unambiguous resolved lockfile; only exact public pins can be checked and transitive coverage is incomplete");
            }
            for declaration in declarations {
                if declaration.len() > 4096 || declaration.contains(['$', '\0']) {
                    inventory.diagnostic_code(
                        &file,
                        "python_manifest_unresolved",
                        "Python manifest requirement is unsupported",
                    );
                    continue;
                }
                let mut nesting = 0usize;
                let mut too_deep = false;
                for c in declaration.chars() {
                    if c == '(' {
                        nesting += 1
                    }
                    if c == ')' {
                        nesting = nesting.saturating_sub(1)
                    }
                    if nesting > 32 {
                        too_deep = true;
                        break;
                    }
                }
                if too_deep {
                    inventory.diagnostic_code(
                        &file,
                        "python_manifest_unresolved",
                        "Python requirement nesting exceeds limit",
                    );
                    continue;
                }
                let mut warnings = crate::requirements::Warnings::default();
                let parsed = Requirement::<VerbatimUrl>::parse_reporter(
                    &declaration,
                    Path::new("."),
                    &mut warnings,
                );
                if warnings.0 {
                    inventory.diagnostic_code(
                        &file,
                        "python_manifest_unresolved",
                        "Python requirement marker is unsupported",
                    );
                    continue;
                }
                let Ok(requirement) = parsed else {
                    inventory.diagnostic_code(&file,"python_version_unresolved","Python manifest version syntax is unsupported or unresolved; use a supported lockfile");
                    continue;
                };
                if matches!(requirement.version_or_url, Some(VersionOrUrl::Url(_))) {
                    inventory.diagnostic_code(&file,"python_source_uncovered","Python manifest uses a direct or local source; it is not queried as public PyPI");
                    continue;
                }
                let specs = match &requirement.version_or_url {
                    Some(VersionOrUrl::VersionSpecifier(s)) => Some(s),
                    _ => None,
                };
                if let Some(owner) = owned {
                    let lock_files = [
                        label(root, &owner.join("uv.lock")),
                        label(root, &owner.join("poetry.lock")),
                    ];
                    let matches = inventory.packages.iter().any(|(p, files)| {
                        p.ecosystem == "PyPI"
                            && p.name == requirement.name.as_ref()
                            && files.iter().any(|f| lock_files.contains(f))
                            && p.version
                                .parse()
                                .is_ok_and(|v| specs.is_none_or(|s| s.contains(&v)))
                    });
                    let local = self.manifests.iter().any(|(p, v)| {
                        self.owners.get(p) == Some(owner)
                            && project_name(v)
                                .is_some_and(|n| normalized(n) == requirement.name.as_ref())
                    });
                    if !matches && !local {
                        inventory.diagnostic_code(&file,"python_manifest_unresolved","Declared Python dependency has no compatible covered lockfile identity; regenerate or reconcile the project lockfile");
                    }
                } else if has_source_overrides {
                    inventory.diagnostic_code(&file,"python_source_uncovered","Manifest source overrides prevent unambiguous public-PyPI lookup without a lockfile");
                } else {
                    let candidates: Vec<_> = specs
                        .into_iter()
                        .flat_map(|s| s.iter())
                        .filter(|s| *s.operator() == Operator::Equal)
                        .collect();
                    if candidates.len() != 1 {
                        inventory.diagnostic_code(
                            &file,
                            "python_version_unresolved",
                            "Python manifest requirement needs an exact pin or resolved lockfile",
                        );
                        continue;
                    }
                    let version = candidates[0].version();
                    if specs.is_some_and(|s| !s.contains(version)) {
                        inventory.diagnostic_code(
                            &file,
                            "python_constraint_conflict",
                            "Python manifest exact version conflicts with its other specifiers",
                        );
                        continue;
                    }
                    if let Err(e) = inventory.insert(
                        Package {
                            ecosystem: "PyPI".into(),
                            name: requirement.name.to_string(),
                            version: version.to_string(),
                        },
                        &file,
                    ) {
                        inventory.diagnostic(&file, e.0);
                    }
                }
            }
        }
        inventory.inputs.sort();
        inventory.inputs.dedup();
    }
}
fn project_name(v: &toml::Value) -> Option<&str> {
    v.get("project")
        .and_then(|v| v.get("name"))
        .or_else(|| {
            v.get("tool")
                .and_then(|v| v.get("poetry"))
                .and_then(|v| v.get("name"))
        })
        .and_then(toml::Value::as_str)
}
fn normalized(s: &str) -> String {
    s.split(['_', '.', '-'])
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-")
}
fn safe_path(s: &str) -> bool {
    !s.is_empty()
        && !s.contains(['\\', ':', '\0'])
        && !Path::new(s).is_absolute()
        && !s.split('/').any(|p| p == "..")
}
fn compile_patterns(v: Option<&toml::Value>) -> Result<globset::GlobSet, ()> {
    let mut builder = globset::GlobSetBuilder::new();
    if let Some(v) = v {
        let a = v.as_array().ok_or(())?;
        if a.len() > 256 {
            return Err(());
        }
        for p in a {
            let p = p.as_str().ok_or(())?;
            if !safe_path(p) || p.len() > 1024 {
                return Err(());
            }
            builder.add(globset::Glob::new(p).map_err(|_| ())?);
        }
    }
    builder.build().map_err(|_| ())
}

fn strings(v: Option<&toml::Value>, out: &mut Vec<String>, file: &str, i: &mut Inventory) {
    if let Some(v) = v {
        if let Some(a) = v.as_array() {
            for v in a {
                if let Some(s) = v.as_str() {
                    out.push(s.into())
                } else {
                    i.diagnostic_code(
                        file,
                        "python_manifest_unresolved",
                        "Python dependency declaration must be a string",
                    )
                }
            }
        } else {
            i.diagnostic_code(
                file,
                "python_manifest_unresolved",
                "Python dependency declarations must be arrays",
            )
        }
    }
}
fn poetry_declarations(v: &toml::Value, out: &mut Vec<String>, file: &str, i: &mut Inventory) {
    let Some(table) = v.as_table() else {
        i.diagnostic_code(
            file,
            "python_manifest_unresolved",
            "Poetry dependencies must be a table",
        );
        return;
    };
    for (name, value) in table {
        if name == "python" {
            continue;
        }
        let version = value
            .as_str()
            .or_else(|| value.get("version").and_then(toml::Value::as_str));
        if value.as_table().is_some_and(|t| {
            t.keys()
                .any(|k| matches!(k.as_str(), "git" | "url" | "path" | "source"))
        }) {
            i.diagnostic_code(
                file,
                "python_source_uncovered",
                "Poetry dependency has a private or non-registry source",
            );
            continue;
        }
        if let Some(v) = version {
            let spec = if v == "*" {
                "".into()
            } else if v.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
                format!("=={v}")
            } else if v.starts_with(['^', '~']) {
                match poetry_range(v) {
                    Some(spec) => spec,
                    None => {
                        i.diagnostic_code(
                            file,
                            "python_version_unresolved",
                            "Unsupported Poetry version range; use a supported exact constraint",
                        );
                        continue;
                    }
                }
            } else {
                v.into()
            };
            out.push(format!("{name}{spec}"))
        } else {
            i.diagnostic_code(
                file,
                "python_manifest_unresolved",
                "Poetry dependency version is unresolved",
            )
        }
    }
}
fn label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn poetry_range(value: &str) -> Option<String> {
    let operator = value.chars().next()?;
    let base = &value[1..];
    if base.is_empty() || !base.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        return None;
    }
    let parts: Vec<u64> = base
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let index = if operator == '~' {
        if parts.len() > 1 {
            1
        } else {
            0
        }
    } else {
        parts
            .iter()
            .position(|n| *n != 0)
            .unwrap_or(parts.len() - 1)
    };
    let mut upper = parts[..=index].to_vec();
    upper[index] = upper[index].checked_add(1)?;
    Some(format!(
        ">={base},<{}",
        upper
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".")
    ))
}

fn group_valid(
    name: &str,
    groups: &toml::map::Map<String, toml::Value>,
    active: &mut BTreeSet<String>,
    done: &mut BTreeSet<String>,
) -> bool {
    if done.contains(name) {
        return true;
    }
    if active.len() >= 16 || !active.insert(name.into()) {
        return false;
    }
    let Some(entries) = groups.get(name).and_then(toml::Value::as_array) else {
        return false;
    };
    for e in entries {
        if let Some(target) = e.get("include-group").and_then(toml::Value::as_str) {
            if !group_valid(target, groups, active, done) {
                return false;
            }
        }
    }
    active.remove(name);
    done.insert(name.into());
    true
}
