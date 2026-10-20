# Install Sentinel 0.0.1

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

Scan exit codes: 0 complete without threshold findings, 4 findings at the threshold, and 7 incomplete coverage/intelligence. Use `scan --type secrets` for local secrets only or `scan --type dependencies` for dependency intelligence only. `--offline` never queries OSV. Policies define decisions; no runtime agent enforcement is provided.
