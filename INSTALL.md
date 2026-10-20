# Install Sentinel 0.0.2

Install on supported macOS or GNU/Linux systems:

```sh
curl -fsSL https://raw.githubusercontent.com/adriennie/sentinel-releases/main/install.sh | bash
```

The public download repository is [adriennie/sentinel-releases](https://github.com/adriennie/sentinel-releases). It contains the installer and verified release binaries; the main source repository remains private. `latest` selects the latest published download release.

To inspect the script first or select a version:

```sh
curl -fsSL https://raw.githubusercontent.com/adriennie/sentinel-releases/main/install.sh -o sentinel-install.sh
bash sentinel-install.sh --help
bash sentinel-install.sh --version 0.0.2
# Explicit replacement of an existing installation:
bash sentinel-install.sh --version 0.0.2 --force
```

From a source checkout, private published releases remain available with authenticated GitHub CLI access:

```sh
bash install.sh --repository adriennie/Sentinel-cli --github
```

Override the release repository with `--repository OWNER/REPO`. Private draft releases are refused by the installer; public releases are distributed separately without modifying the private draft.

The default destination is `~/.local/bin`. Override it with `--install-dir /absolute/path` or `SENTINEL_INSTALL_DIR`. To pass installer options through a pipe, use `bash -s -- --version 0.0.2`. Existing binaries are preserved unless `--force` is supplied; symlink destinations are rejected. The installer downloads only over HTTPS, checks the selected archive against `SHA256SUMS`, extracts only the single expected regular binary, verifies its version, and replaces it atomically. It leaves shell profiles unchanged and prints the PATH command when needed. Checksums detect corrupted downloads; they are not independent signatures against a compromised release publisher. As with any `curl | bash` installation, trust the source of the installer itself, or download and inspect it first.

Native Windows users should use the ZIP installation below; there is no PowerShell installer in this change. GNU/Linux ARM64 and musl builds are not currently published.

Select the archive matching your operating system and CPU. Linux binaries target x86_64 GNU/Linux (glibc 2.39 or newer); Windows binaries target x86_64 MSVC; macOS binaries target either Intel x86_64 (macOS 13+) or Apple Silicon aarch64 (macOS 13+).

Verify the archive against SHA256SUMS before extraction. On Linux use `sha256sum -c SHA256SUMS`; on macOS use `shasum -a 256 -c SHA256SUMS`. On Windows compare `(Get-FileHash <archive> -Algorithm SHA256).Hash` with its entry in SHA256SUMS. Only compare entries for downloaded files.

Extract the archive and place `sentinel` (or `sentinel.exe`) on PATH. These initial binaries are unsigned and not notarized. Building from source remains available using the pinned Rust toolchain:

```sh
cargo install --locked --path crates/sentinel-cli
sentinel --version
sentinel init
sentinel scan --format json
sentinel doctor
sentinel audit --limit 50
```

Scan exit codes: 0 complete without threshold findings, 4 findings at the threshold, and 7 incomplete coverage/intelligence. Use `scan --type secrets` for local secrets only or `scan --type dependencies` for dependency intelligence only. `--offline` never queries OSV. Agent gating is opt-in: install Claude Code 2.1.304+ within major version 2, then use `sentinel agent setup claude`, inspect `sentinel agent status`, and launch `sentinel guard --scope 'src/**' -- claude`. Review docs/v0.0.2-security.md first. Hooks are not an OS sandbox. New commands do not alter existing version-1 policy files automatically.
