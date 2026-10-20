# Dependency scanning

```sh
sentinel init
sentinel scan --type dependencies
sentinel scan --offline --format json
sentinel scan --fail-on critical
sentinel scan --sbom ./bom.json --format json
```

This milestone scans resolved dependencies only. It does not run package managers, build scripts, source-code analysis, or secrets scanning. `scan` currently defaults to `--type dependencies`; `--type secrets` remains unavailable. An initialized, valid policy with `scanning.dependencies: true` is required. CLI `--offline` or policy `scanning.offline: true` disables network access.

## Coverage

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

OSV advisory IDs remain distinct; aliases between different advisories are not merged. Withdrawn advisories are omitted. Severity is the maximum supported OSV categorical label or computed CVSS v3 base score, including package-specific severity. Missing, malformed, CVSS v2-only, or CVSS v4-only severity remains `unknown` when no supported severity is present. Unknown severity conservatively exceeds every failure threshold. Findings have stable IDs, `DEP-001`, OSV evidence, remediation guidance, and reachability `not_analyzed`. Raw advisory descriptions and lockfile parser excerpts are omitted.

## Results and exit codes

Text output lists findings, coverage diagnostics, and cache ages. `--quiet` suppresses the summary but preserves findings and diagnostics. JSON emits one versioned envelope on stdout, with a scan report in `data`. Reports contain `coverage`, `inputs`, `status`, `complete`, discovered/checked counts, findings, diagnostics (including affected package identities), and cache ages, plus `audit_logging` describing completion-event persistence. Envelope status `ok` means the scan command ran; inspect `data.complete`, `data.status`, and the process exit code for its security outcome.

- `0`: complete within the stated scope, no finding at the selected threshold.
- `4`: complete scan with findings at/above `--fail-on` (default `high`), or unknown-severity findings.
- `7`: incomplete coverage or unavailable intelligence; this takes precedence over findings, which remain in the output.
- `2`: invalid arguments; `3`: invalid/missing policy or dependency scanning disabled; `1`: unexpected application/filesystem failure.

## Verification

Required tests use synthetic OSV clients and local HTTP servers, never live vulnerability APIs. They cover registry identity parsing, supported SBOM mappings, npm workspaces/aliases, findings, clean supported fixtures, pagination, malformed responses, cache reuse/staleness/corruption, symlink exclusions, unknown severity, policy toggles, and CLI JSON/exit codes. Live smoke checks are separate from CI.

CycloneDX component identification follows its [software-component inventory model](https://www.cyclonedx.org/use-cases/software-components/).
