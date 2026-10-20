# Dependency scanning

```sh
sentinel init
sentinel scan --type dependencies
sentinel scan --offline --format json
sentinel scan --fail-on critical
sentinel scan --sbom ./bom.json --format json
```

Dependency scanning inspects resolved package identities. It does not run package managers, build scripts, or source-code analysis. Unqualified `scan` also runs policy-enabled local secrets scanning; use `--type dependencies` to select only dependency lookup. An initialized, valid policy with `scanning.dependencies: true` is required. CLI `--offline` or policy `scanning.offline: true` disables network access.

## Coverage

### Unreleased v0.0.2 work

The development source now discovers `uv.lock` version 1, with absent revision or revisions 0–5, and extracts exact public-PyPI registry identities. Names are normalized for PyPI lookup and Python release/prerelease/post/dev/local version spellings are accepted without Rust SemVer conversion. Unrecognized version spellings remain explicitly uncovered. Discovery reuses the existing OSV client, cache, limits, deduplication and result contracts. It never invokes Python or a package manager.

Private registries, Git, URL, editable and local sources remain uncovered, as do unsupported schema revisions. Poetry lockfile versions 1.1, 2.0, and 2.1 are also discovered automatically. Packages without source metadata use Poetry’s default PyPI source; explicit public-PyPI legacy sources are accepted, and other source types remain uncovered. All listed groups and platform alternatives are inventoried. Coexisting uv/Poetry locks retain known packages and locations but report ambiguous authority.

Manifest reconciliation and workspace ownership are still pending; `pyproject.toml` therefore continues to produce an incomplete-coverage diagnostic even alongside a parsed uv lockfile. Completeness is relative to the inventory, not proof of lockfile freshness or installed-environment equivalence. The published v0.0.1 draft binaries do not contain these changes.

The parser follows the producer's [versioned lockfile description](https://docs.astral.sh/uv/concepts/resolution/) and [representative lockfile](https://github.com/astral-sh/uv/blob/main/uv.lock). uv warns that its lockfile is not a stable public format, so schema gates and compatibility fixtures must be maintained. Poetry source/default-index and schema handling follow its [lockfile reader](https://github.com/python-poetry/poetry/blob/main/src/poetry/packages/locker.py).

#### Requirements inventories

Discovery recognizes `requirements.txt`, `requirements-*.txt`, and `.txt` files immediately inside a `requirements` directory. It reads pinned public-PyPI packages directly, including normalized names, extras, validated environment markers, comments, UTF-8, continuations, and syntactically valid SHA-256/384/512 `--hash` options. Hashes are not verified against artifacts: Sentinel does not download or install packages. Listed platform alternatives are inventoried without evaluating the current Python environment.

Local `-r`/`--requirement` and `-c`/`--constraint` includes support separated arguments, attached short arguments, and `--option=path`. Paths resolve relative to the including file, must remain inside the selected project, and must be regular files visible to the existing discovery walk. Absolute paths, parent traversal, remote URLs, environment expansion, quoted include paths, symlinks, and ignored/excluded files are rejected. Referenced files are processed in their include context instead of becoming independent root inventories. Cycles are explicit failures. A requirement include inside a constraint file is unsupported rather than silently changing its role.

Constraints do not introduce packages. An exact `==` pin in a requirement or its unconditional constraints supplies the candidate version; all applicable supported specifiers must accept it. Ranges without an exact candidate, conflicting pins, wildcard-only pins, arbitrary `===` equality, conditional constraints and constraint extras remain uncovered. Constraints from separate root inventories are not mixed. Package evidence retains requirement and applicable constraint locations.

Source/index directives and unsupported pip options make public-registry provenance uncertain. Sentinel withholds lookups for the affected include graph rather than guessing PyPI identities. Missing includes and malformed/direct-reference constraint input also withhold that graph's lookups. Other independent inventories and lockfiles remain available, with findings preserved. `--require-hashes` and `--no-require-hashes` are recognized without changing dependency identities. No pip config, environment variables, virtual environment, resolver, or package manager is consulted.

**Requirements-only scans remain incomplete (exit 7)** even after every listed exact identity is checked: the file does not prove that all transitive dependencies are present. Findings are still returned. Use a supported resolved lockfile when whole-project inventory coverage is required; SBOM input remains optional.

Requirements and their includes share the 256-input discovery allowance with native lockfiles. Requirements reads additionally have a 64 MiB aggregate budget, 16 MiB per file, 16 include levels, 100,000 physical lines, 16 KiB logical lines, 32 expression nesting levels, and a bounded constraint-evaluation budget. Budget exhaustion is explicit incomplete coverage. Each file is parsed once; graph traversal is deduplicated by file and role.

Syntax follows the supported subset of [pip's requirements format](https://pip.pypa.io/en/stable/reference/requirements-file-format/) and [constraint semantics](https://pip.pypa.io/en/stable/user_guide/#constraints-files). The new `pep508_rs` 0.9.2 parser and its `pep440_rs` 0.7.3 dependency implement Python requirement/marker and version/specifier semantics; both declare `Apache-2.0 OR BSD-2-Clause` and bundle license texts. Default features are disabled for the direct parser dependency, including tracing, so parser warnings are handled internally without emitting input text. Cargo.lock records the dependency graph; fresh vulnerability-review evidence is required before a new release.

### Released v0.0.1

Native discovery supports crates.io registry dependencies in Cargo lockfiles (legacy unversioned and versions 1–4) and npm registry dependencies in package-lock.json versions 2/3. Development, optional, and transitive dependencies are included when listed in these files, regardless of the current platform. Duplicate ecosystem/name/version tuples are queried once; findings retain all lockfile locations. npm scopes, aliases, nested packages, and lockfile workspace entries are supported. Workspace/local project entries are not queried as public registry packages. Git and alternate-registry dependencies are reported as uncovered.

Discovery walks nested projects, respects gitignore rules (also outside a Git checkout), and does not follow symlinks. It excludes `.git`, `.sentinel`, `node_modules`, `target`, `vendor`, `dist`, `build`, `.venv`, and `venv`. Discovery stops after 100,000 entries or 64 directory levels and reports incomplete coverage. At most 256 lockfiles are read. Input files are bounded to 16 MiB, inventories to 10,000 unique packages, and reports to 100,000 findings. Exceeding these limits makes the scan incomplete. Excluded/ignored files are outside scan coverage. Known unsupported manifests or lockfiles are reported as incomplete, even in a mixed supported project. Files in unknown formats cannot be reliably identified automatically.

For other languages, provide a **CycloneDX JSON 1.4–1.7 SBOM** with versioned Package URLs. SBOM mode scans the supplied component inventory instead of discovering lockfiles; completeness is relative to that inventory. The producer is responsible for including the full resolved dependency graph. Nested components are included. Missing versions/PURLs, unsupported types, qualifiers/subpaths, and conflicting versions are reported as incomplete. This is a dependency-inventory reader, not a complete CycloneDX schema validator.

Supported PURL mappings:

| PURL type | OSV ecosystem | Common projects |
| --- | --- | --- |
| cargo | crates.io | Rust |
| npm | npm | JavaScript, TypeScript |
| pypi | PyPI | Python |
| maven | Maven | Java, Kotlin, Scala |
| golang | Go | Go |
| gem | RubyGems | Ruby |
| nuget | NuGet | C#, F# |
| composer | Packagist | PHP |
| hex | Hex | Elixir, Erlang |
| pub | Pub | Dart, Flutter |

There is no universal language/project coverage. Native Python, Maven, Go, Ruby, .NET, PHP, and other lockfile parsers are not implemented yet. C/C++ generic identities, OS packages, private registries, and packages outside OSV coverage are not covered. An empty advisory response means only that OSV returned no known advisory for that queried identity; it does not establish project security or package support independently.

## OSV and cache

The client uses the [official version-query API](https://google.github.io/osv.dev/post-v1-query/), including pagination, over HTTPS with redirects disabled. Online requests disclose package names, versions, and ecosystems to OSV. Source files and credentials are not uploaded. Up to eight unique packages are queried concurrently; requests have a five-second connection timeout and a twenty-second total query budget. Responses are bounded to 16 MiB, twenty pages, and 10,000 advisories per package. New lookup batches stop after a two-minute scan budget; the current batch can finish afterward. Budget exhaustion is incomplete; rerunning can reuse successfully cached work.

Cache records are atomically written under `.sentinel/cache/osv-v1/`, keyed by a SHA-256 hash of the exact package identity. Both vulnerable and empty successful responses are cached with a UNIX timestamp. Fresh entries (at most 24 hours old) are reused online and offline; cache ages appear in the report. Corrupt, mismatched, future-dated, unavailable, or missing cache data cannot produce a complete offline scan. Stale records retain findings but make an offline scan incomplete. Failed online refreshes can retain stale findings and remain incomplete. Cache-write failures are reported as incomplete too. Cache files are local intelligence, not tamper-evident evidence; deleting the cache forces a fresh online lookup. Symlink cache directories and input files are rejected, but this is not an OS sandbox against concurrent filesystem tampering.

OSV advisory IDs remain distinct; aliases between different advisories are not merged. Withdrawn advisories are omitted. Maintenance information is classified only from explicit top-level or matching package-specific advisory metadata; unclassified advisory types remain visible with a generic security-advisory title. Legacy cache entries default to unclassified. Threshold behavior remains conservative and no maintenance advisories are silently suppressed. Severity is the maximum supported OSV categorical label or computed CVSS v3 base score, including package-specific severity. Missing, malformed, CVSS v2-only, or CVSS v4-only severity remains `unknown` when no supported severity is present. Unknown severity conservatively exceeds every failure threshold. Findings have stable IDs, `DEP-001`, OSV evidence, remediation guidance, and reachability `not_analyzed`. Raw advisory descriptions and lockfile parser excerpts are omitted.

## Results and exit codes

Unreleased Python diagnostics retain the version-1 report shape and use stable codes: `python_lock_conflict`, `python_version_unresolved`, `python_constraint_conflict`, `python_source_uncovered`, and `python_inventory_partial`. The existing `unsupported_dependency` code remains for other unsupported/malformed inputs. Conflicting uv/Poetry locks retain known package identities from both inputs and report incomplete coverage; exact matching identities are deduplicated with all source locations retained. Missing versions are never guessed, and source URLs and embedded credentials are omitted from messages. Dependency findings remain visible when exit 7 takes precedence.


Text output lists findings, coverage diagnostics, and cache ages. `--quiet` suppresses the summary but preserves findings and diagnostics. JSON emits one versioned envelope on stdout, with a scan report in `data`. Reports contain `coverage`, `inputs`, `status`, `complete`, discovered/checked counts, findings, diagnostics (including affected package identities), and cache ages, plus `audit_logging` describing completion-event persistence. Envelope status `ok` means the scan command ran; inspect `data.complete`, `data.status`, and the process exit code for its security outcome.

- `0`: complete within the stated scope, no finding at the selected threshold.
- `4`: complete scan with findings at/above `--fail-on` (default `high`), or unknown-severity findings.
- `7`: incomplete coverage or unavailable intelligence; this takes precedence over findings, which remain in the output.
- `2`: invalid arguments; `3`: invalid/missing policy or dependency scanning disabled; `1`: unexpected application/filesystem failure.

## Verification

Required tests use synthetic OSV clients and local HTTP servers, never live vulnerability APIs. They cover registry identity parsing, supported SBOM mappings, npm workspaces/aliases, findings, clean supported fixtures, pagination, malformed responses, cache reuse/staleness/corruption, symlink exclusions, unknown severity, policy toggles, and CLI JSON/exit codes. Live smoke checks are separate from CI.

CycloneDX component identification follows its [software-component inventory model](https://www.cyclonedx.org/use-cases/software-components/).
