//! Read-only requirements inventories. Includes never escape discovered project files.
use crate::{bounded_read, Inventory, Package, MAX_INPUT_BYTES};
use pep508_rs::{
    pep440_rs::{Operator, Version, VersionSpecifiers},
    MarkerWarningKind, Reporter, Requirement, VerbatimUrl, VersionOrUrl,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LINES: usize = 100_000;
const MAX_DEPTH: usize = 16;
const MAX_LINE: usize = 16 * 1024;

struct Entry {
    requirement: Requirement,
    file: String,
}
#[derive(Default)]
struct Node {
    entries: Vec<Entry>,
    edges: Vec<(PathBuf, bool)>,
    unsafe_source: bool,
}
#[derive(Default)]
struct Warnings(bool);
impl Reporter for Warnings {
    fn report(&mut self, _: MarkerWarningKind, _: String) {
        self.0 = true;
    }
}

pub(crate) fn is_requirements(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    name == "requirements.txt"
        || (name.starts_with("requirements-") && name.ends_with(".txt"))
        || (name.ends_with(".txt")
            && path
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|p| p == "requirements"))
}

struct Reader<'a> {
    root: &'a Path,
    allowed: &'a BTreeSet<PathBuf>,
    nodes: BTreeMap<PathBuf, Node>,
    attempted: BTreeSet<PathBuf>,
    max_files: usize,
    bytes: u64,
    lines: usize,
    inventory: &'a mut Inventory,
}
impl Reader<'_> {
    fn label(&self, path: &Path) -> String {
        // Only discovered paths become labels; rejected include text is never echoed.
        path.strip_prefix(self.root)
            .unwrap_or(Path::new("<requirements>"))
            .to_string_lossy()
            .replace('\\', "/")
    }

    fn load(&mut self, path: &Path, depth: usize) {
        if self.attempted.contains(path) {
            return;
        }
        let file = self.label(path);
        if depth > MAX_DEPTH || self.attempted.len() >= self.max_files || self.bytes >= MAX_BYTES {
            self.inventory
                .diagnostic(&file, "Requirements include budget exceeded");
            return;
        }
        self.attempted.insert(path.to_path_buf());
        // Reject symlinks in every component, including directory components.
        let safe = path.strip_prefix(self.root).ok().is_some_and(|relative| {
            let mut current = self.root.to_path_buf();
            relative.components().all(|part| {
                if !matches!(part, Component::Normal(_)) {
                    return false;
                }
                current.push(part);
                std::fs::symlink_metadata(&current).is_ok_and(|m| !m.file_type().is_symlink())
            })
        });
        if !safe || !self.allowed.contains(path) {
            self.inventory.diagnostic(
                &file,
                "Requirements include is unavailable, ignored, or unsafe",
            );
            return;
        }
        let bytes = match bounded_read(path, MAX_INPUT_BYTES.min(MAX_BYTES - self.bytes)) {
            Ok(bytes) => bytes,
            Err(error) => {
                // Charge the bounded attempted read even when it failed.
                self.bytes = (self.bytes + MAX_INPUT_BYTES).min(MAX_BYTES);
                self.inventory.diagnostic(&file, error.0);
                return;
            }
        };
        self.bytes += bytes.len() as u64;
        if !self.inventory.inputs.contains(&file) {
            self.inventory.inputs.push(file.clone());
        }
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => {
                self.inventory
                    .diagnostic(&file, "Requirements input must be UTF-8");
                return;
            }
        };
        let mut node = Node::default();
        let mut logical = String::new();
        for physical in text.lines() {
            self.lines += 1;
            if self.lines > MAX_LINES {
                self.inventory
                    .diagnostic(&file, "Requirements line budget exceeded");
                node.unsafe_source = true;
                break;
            }
            if logical.len() + physical.len() > MAX_LINE {
                self.inventory
                    .diagnostic(&file, "Requirements logical line exceeds size limit");
                node.unsafe_source = true;
                break;
            }
            logical.push_str(physical.trim_end_matches('\r'));
            let slashes = logical.bytes().rev().take_while(|b| *b == b'\\').count();
            if slashes % 2 == 1 {
                logical.pop();
                continue;
            }
            let line = strip_comment(&logical).trim();
            if !line.is_empty() {
                self.line(line, path, &file, &mut node);
            }
            logical.clear();
        }
        if !logical.is_empty() {
            self.inventory
                .diagnostic(&file, "Unterminated requirements continuation");
            node.unsafe_source = true;
        }
        let edges = node.edges.clone();
        self.nodes.insert(path.to_path_buf(), node);
        for (target, _) in edges {
            self.load(&target, depth + 1);
        }
    }

    fn line(&mut self, line: &str, path: &Path, file: &str, node: &mut Node) {
        if line.contains(['$', '\0']) {
            self.inventory.diagnostic(
                file,
                "Requirements environment expansion or invalid input is unsupported",
            );
            node.unsafe_source = true;
            return;
        }
        if let Some((target, constraint)) = include(line) {
            let target = target.trim();
            if target.is_empty()
                || target.contains(['\\', ':', '%', '#', '\'', '"'])
                || target.chars().any(char::is_control)
                || Path::new(target).is_absolute()
                || Path::new(target)
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
            {
                self.inventory.diagnostic(
                    file,
                    "Requirements includes must be safe project-relative file paths",
                );
                node.unsafe_source = true;
            } else if let Some(parent) = path.parent() {
                let mut resolved = parent.to_path_buf();
                for part in Path::new(target).components() {
                    if let Component::Normal(part) = part {
                        resolved.push(part);
                    }
                }
                node.edges.push((resolved, constraint));
            }
            return;
        }
        if matches!(line, "--require-hashes" | "--no-require-hashes") {
            return;
        }
        if line.starts_with('-') {
            self.inventory.diagnostic(file, "Requirements source or pip option is unsupported; public registry provenance is uncertain");
            node.unsafe_source = true;
            return;
        }
        let (spec, hashes) = line
            .split_once(" --hash")
            .map_or((line, None), |(s, h)| (s, Some(h)));
        if let Some(hashes) = hashes {
            if !valid_hashes(hashes) {
                node.unsafe_source = true;
                self.inventory
                    .diagnostic(file, "Malformed or unsupported requirements hash option");
                return;
            }
        }
        let mut depth = 0usize;
        for c in spec.chars() {
            if c == '(' {
                depth += 1;
            }
            if c == ')' {
                depth = depth.saturating_sub(1);
            }
            if depth > 32 {
                node.unsafe_source = true;
                self.inventory
                    .diagnostic(file, "Requirements expression nesting limit exceeded");
                return;
            }
        }
        let mut warnings = Warnings::default();
        let parsed =
            Requirement::<VerbatimUrl>::parse_reporter(spec, Path::new("."), &mut warnings);
        match parsed {
            Ok(requirement) if !warnings.0 => {
                if matches!(requirement.version_or_url, Some(VersionOrUrl::Url(_))) {
                    node.unsafe_source = true;
                    self.inventory.diagnostic(file, "Python direct URL, Git, or local requirement is outside public registry coverage");
                } else {
                    node.entries.push(Entry {
                        requirement,
                        file: file.into(),
                    });
                }
            }
            _ => {
                node.unsafe_source = true;
                self.inventory
                    .diagnostic(file, "Malformed or unsupported Python requirement");
            }
        }
    }
}

fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    let mut whitespace = true;
    for (i, c) in line.char_indices() {
        if matches!(c, '\'' | '"') {
            if quote == Some(c) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(c);
            }
        }
        if c == '#' && whitespace && quote.is_none() {
            return &line[..i];
        }
        whitespace = c.is_whitespace();
    }
    line
}

fn include(line: &str) -> Option<(&str, bool)> {
    for (long, short, constraint) in [("--requirement", "-r", false), ("--constraint", "-c", true)]
    {
        if let Some(rest) = line.strip_prefix(long) {
            if let Some(rest) = rest.strip_prefix('=') {
                return Some((rest, constraint));
            }
            if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                return Some((rest, constraint));
            }
        }
        if let Some(rest) = line.strip_prefix(short) {
            return Some((rest, constraint));
        }
    }
    None
}

fn valid_hashes(value: &str) -> bool {
    // First --hash was split off; retain strict validation of every remaining option.
    let rest = format!("--hash{value}");
    let mut tokens = rest.split_whitespace();
    while let Some(token) = tokens.next() {
        let hash = if token == "--hash" {
            tokens.next().unwrap_or("")
        } else if let Some(hash) = token.strip_prefix("--hash=") {
            hash
        } else {
            return false;
        };
        let Some((algorithm, digest)) = hash.split_once(':') else {
            return false;
        };
        let length = match algorithm {
            "sha256" => 64,
            "sha384" => 96,
            "sha512" => 128,
            _ => return false,
        };
        if digest.len() != length || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

struct Collection<'a> {
    nodes: &'a BTreeMap<PathBuf, Node>,
    active: BTreeSet<PathBuf>,
    seen: BTreeSet<(PathBuf, bool)>,
    entries: Vec<(&'a Entry, bool)>,
    unsafe_source: bool,
}
impl<'a> Collection<'a> {
    fn collect(&mut self, path: &Path, constraint: bool, depth: usize) {
        if depth > MAX_DEPTH || self.active.contains(path) {
            self.unsafe_source = true;
            return;
        }
        if !self.seen.insert((path.to_path_buf(), constraint)) {
            return;
        }
        self.active.insert(path.to_path_buf());
        if let Some(node) = self.nodes.get(path) {
            self.unsafe_source |= node.unsafe_source;
            if self.entries.len() + node.entries.len() > MAX_LINES {
                self.unsafe_source = true;
                return;
            }
            self.entries
                .extend(node.entries.iter().map(|entry| (entry, constraint)));
            for (target, nested_constraint) in &node.edges {
                if constraint && !nested_constraint {
                    self.unsafe_source = true;
                    continue;
                }
                self.collect(target, *nested_constraint, depth + 1);
            }
        } else {
            self.unsafe_source = true;
        }
        self.active.remove(path);
    }
}

pub(crate) fn scan_requirements(
    root: &Path,
    candidates: &[PathBuf],
    allowed: &BTreeSet<PathBuf>,
    max_files: usize,
    inventory: &mut Inventory,
) {
    if candidates.is_empty() {
        return;
    }
    let mut reader = Reader {
        root,
        allowed,
        max_files,
        nodes: BTreeMap::new(),
        attempted: BTreeSet::new(),
        bytes: 0,
        lines: 0,
        inventory,
    };
    for path in candidates {
        reader.load(path, 0);
    }
    let referenced: BTreeSet<_> = reader
        .nodes
        .values()
        .flat_map(|n| n.edges.iter().map(|(p, _)| p.clone()))
        .collect();
    let mut roots: Vec<_> = candidates
        .iter()
        .filter(|p| !referenced.contains(*p))
        .collect();
    // A component consisting only of a cycle must still produce a diagnostic.
    let mut covered = BTreeSet::new();
    for path in &roots {
        mark_reachable(path, &reader.nodes, &mut covered);
    }
    for path in candidates {
        if !covered.contains(path) {
            roots.push(path);
            mark_reachable(path, &reader.nodes, &mut covered);
        }
    }
    let mut comparisons = 0usize;
    for path in roots {
        let file = reader.label(path);
        let mut collection = Collection {
            nodes: &reader.nodes,
            active: BTreeSet::new(),
            seen: BTreeSet::new(),
            entries: Vec::new(),
            unsafe_source: false,
        };
        collection.collect(path, false, 0);
        let entries = collection.entries;
        let unsafe_source = collection.unsafe_source;
        reader.inventory.diagnostic_code(&file, "python_inventory_partial", "Requirements inventory does not establish complete transitive dependency coverage; use a supported resolved lockfile for project coverage");
        if unsafe_source {
            reader.inventory.diagnostic_code(&file, "python_source_uncovered", "Requirements include graph or source configuration is incomplete; public registry lookups for this inventory are withheld");
            continue;
        }
        let mut constraints: BTreeMap<String, Vec<&Entry>> = BTreeMap::new();
        for (entry, constraint) in &entries {
            if *constraint {
                constraints
                    .entry(entry.requirement.name.to_string())
                    .or_default()
                    .push(entry);
            }
        }
        for (entry, constraint) in &entries {
            if *constraint {
                continue;
            }
            let applicable = constraints.get(entry.requirement.name.as_ref());
            comparisons = comparisons.saturating_add(1 + applicable.map_or(0, Vec::len));
            if comparisons > MAX_LINES {
                reader
                    .inventory
                    .diagnostic(&file, "Requirements constraint evaluation budget exceeded");
                return;
            }
            let mut specs = Vec::new();
            if let Some(VersionOrUrl::VersionSpecifier(s)) = &entry.requirement.version_or_url {
                specs.push(s);
            }
            let mut locations = BTreeSet::from([entry.file.clone()]);
            let mut ambiguous = false;
            for c in applicable.into_iter().flatten() {
                if !c.requirement.marker.is_true() || !c.requirement.extras.is_empty() {
                    ambiguous = true;
                } else if let Some(VersionOrUrl::VersionSpecifier(s)) =
                    &c.requirement.version_or_url
                {
                    specs.push(s);
                    locations.insert(c.file.clone());
                } else {
                    ambiguous = true;
                }
            }
            comparisons = comparisons.saturating_add(specs.iter().map(|s| s.len()).sum::<usize>());
            if comparisons > MAX_LINES {
                reader
                    .inventory
                    .diagnostic(&file, "Requirements constraint evaluation budget exceeded");
                return;
            }
            let exact: BTreeSet<Version> = specs
                .iter()
                .flat_map(|s| s.iter())
                .filter(|s| *s.operator() == Operator::Equal)
                .map(|s| s.version().clone())
                .collect();
            if ambiguous || exact.len() != 1 {
                reader.inventory.diagnostic_code(
                    &entry.file,
                    "python_version_unresolved",
                    "Python requirement has no unambiguous exact pin after constraints; use an exact pin or a resolved lockfile",
                );
                continue;
            }
            let version = exact.iter().next().cloned();
            let Some(version) = version else {
                continue;
            };
            if !specs
                .iter()
                .all(|s: &&VersionSpecifiers| s.contains(&version))
            {
                reader.inventory.diagnostic_code(
                    &entry.file,
                    "python_constraint_conflict",
                    "Python requirement conflicts with its version constraints; reconcile pins and constraints with the project package manager",
                );
                continue;
            }
            let package = Package {
                ecosystem: "PyPI".into(),
                name: entry.requirement.name.to_string(),
                version: version.to_string(),
            };
            for location in locations {
                if let Err(error) = reader.inventory.insert(package.clone(), &location) {
                    reader.inventory.diagnostic(&file, error.0);
                    return;
                }
            }
        }
    }
    reader.inventory.inputs.sort();
    reader.inventory.inputs.dedup();
}

fn mark_reachable(path: &Path, nodes: &BTreeMap<PathBuf, Node>, covered: &mut BTreeSet<PathBuf>) {
    if !covered.insert(path.to_path_buf()) {
        return;
    }
    if let Some(node) = nodes.get(path) {
        for (target, _) in &node.edges {
            mark_reachable(target, nodes, covered);
        }
    }
}
