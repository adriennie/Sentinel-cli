#!/usr/bin/env bash
# Sentinel release installer. Requires Bash 3.2+, curl, tar, and SHA-256 tooling.
set -euo pipefail
umask 077

main() {
    local repository=adriennie/Sentinel-cli version=latest github=false force=false
    local install_dir=${SENTINEL_INSTALL_DIR:-${HOME:?HOME must be set}/.local/bin}
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version|--install-dir)
                [ "$#" -ge 2 ] || die "$1 requires a value"
                if [ "$1" = --version ]; then version=$2; else install_dir=$2; fi
                shift 2 ;;
            --github) github=true; shift ;;
            --force) force=true; shift ;;
            -h|--help)
                printf '%s\n' 'Install Sentinel from a published GitHub release.' \
                    'Usage: bash install.sh [--version VERSION] [--install-dir DIR] [--force] [--github]' \
                    'Default: latest published release into ~/.local/bin; no sudo or shell-profile changes.' \
                    '--github uses an already authenticated GitHub CLI for private repositories.'
                return ;;
            *) die "Unknown installer option: $1" ;;
        esac
    done
    local tool os arch target libc major minor
    for tool in uname mktemp tar awk chmod mv wc head tr; do
        command -v "$tool" >/dev/null 2>&1 || die "Required tool is missing: $tool"
    done
    if "$github"; then
        command -v gh >/dev/null 2>&1 || die '--github requires an authenticated GitHub CLI (gh auth login)'
    else
        command -v curl >/dev/null 2>&1 || die 'curl is required'
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        sha_tool=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        sha_tool=shasum
    else die 'sha256sum or shasum is required'; fi
    os=$(uname -s); arch=$(uname -m)
    case "$os/$arch" in
        Darwin/arm64|Darwin/aarch64) target=aarch64-apple-darwin ;;
        Darwin/x86_64|Darwin/amd64) target=x86_64-apple-darwin ;;
        Linux/x86_64|Linux/amd64)
            target=x86_64-unknown-linux-gnu
            libc=$(getconf GNU_LIBC_VERSION 2>/dev/null || true)
            [[ "$libc" =~ ^glibc\ ([0-9]+)\.([0-9]+)$ ]] || die 'Linux archives require glibc 2.39+; use a source build on musl/unknown libc'
            major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}
            (( major > 2 || (major == 2 && minor >= 39) )) || die 'Linux archives require glibc 2.39+; build from source on this system'
            ;;
        *) die "No published archive supports $os/$arch. See INSTALL.md for source builds or Windows installation." ;;
    esac
    local tag final_url
    if [ "$version" = latest ]; then
        if "$github"; then
            tag=$(gh release view --repo "$repository" --json tagName --jq .tagName)
        else
            final_url=$(fetch --output /dev/null --write-out '%{url_effective}' "https://github.com/$repository/releases/latest")
            case "$final_url" in
                "https://github.com/$repository/releases/tag/"*) tag=${final_url##*/} ;;
                *) die 'Cannot resolve a published release; private repositories require --github' ;;
            esac
        fi
    else tag=v${version#v}; fi
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]] || die 'Release version must be a semantic version, for example 0.0.2'
    version=${tag#v}
    [ -n "$install_dir" ] || die 'Install directory cannot be empty'
    case "$install_dir" in /*) ;; *) die 'Install directory must be an absolute path' ;; esac
    [ ! -L "$install_dir/sentinel" ] || die 'Refusing to replace a symlink at the install destination'
    if [ -e "$install_dir/sentinel" ] && ! "$force"; then die 'Sentinel already exists; use --force to replace it'; fi
    [ ! -d "$install_dir/sentinel" ] || die 'Install destination is a directory'
    local asset=sentinel-$version-$target.tar.gz member=sentinel-$version-$target/sentinel
    work=$(mktemp -d "${TMPDIR:-/tmp}/sentinel-install.XXXXXXXX") || die 'Cannot create temporary directory'
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    printf 'Downloading Sentinel %s for %s...\n' "$version" "$target" >&2
    if "$github"; then
        local draft
        draft=$(gh release view "$tag" --repo "$repository" --json isDraft --jq .isDraft)
        [ "$draft" = false ] || die 'The selected release is still an unpublished draft'
        gh release download "$tag" --repo "$repository" --pattern "$asset" --pattern SHA256SUMS --dir "$work"
    else
        fetch --output "$work/SHA256SUMS" "https://github.com/$repository/releases/download/$tag/SHA256SUMS"
        fetch --output "$work/$asset" "https://github.com/$repository/releases/download/$tag/$asset"
    fi
    local expected actual count kind bytes identity
    expected=$(awk -v name="$asset" 'NF == 2 && $2 == name { print $1 }' "$work/SHA256SUMS")
    [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || die 'Missing, duplicate, or malformed archive checksum'
    if [ "$sha_tool" = sha256sum ]; then actual=$(sha256sum "$work/$asset"); else actual=$(shasum -a 256 "$work/$asset"); fi
    actual=${actual%% *}
    [ "$(printf '%s' "$actual" | tr 'A-F' 'a-f')" = "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" ] || die 'Checksum verification failed; nothing was installed'
    count=$(tar -tzf "$work/$asset" | awk -v member="$member" '$0 == member {n++} END {print n+0}')
    [ "$count" = 1 ] || die 'Archive must contain exactly one Sentinel binary'
    kind=$(tar -tvzf "$work/$asset" "$member")
    case "$kind" in -*) ;; *) die 'Archive binary must be a regular file, not a link' ;; esac
    # Extract only the expected member to stdout: no archive paths are created.
    tar -xOzf "$work/$asset" "$member" | head -c 67108865 > "$work/sentinel"
    bytes=$(wc -c < "$work/sentinel")
    [ "$bytes" -gt 0 ] && [ "$bytes" -le 67108864 ] || die 'Archive binary exceeds the size limit or is empty'
    chmod 700 "$work/sentinel"
    identity=$("$work/sentinel" --version) || die 'The verified binary cannot run on this OS; nothing was installed'
    [ "$identity" = "sentinel $version" ] || die 'Binary version does not match the selected release'
    mkdir -p "$install_dir"
    staged=$(mktemp "$install_dir/.sentinel-install.XXXXXXXX") || die 'Cannot write to the install directory'
    cat "$work/sentinel" > "$staged"
    chmod 755 "$staged"
    # Recheck just before rename; keep the previous binary intact on prior failure.
    [ ! -L "$install_dir/sentinel" ] || die 'Install destination became a symlink'
    [ ! -d "$install_dir/sentinel" ] || die 'Install destination became a directory'
    mv -f "$staged" "$install_dir/sentinel"
    staged=
    printf 'Installed %s to %s/sentinel\n' "$identity" "$install_dir"
    case ":${PATH:-}:" in
        *":$install_dir:"*) printf '%s\n' 'Run: sentinel --help' ;;
        *) printf 'Add this directory to PATH in your shell profile:\n  export PATH=%q:$PATH\n' "$install_dir" ;;
    esac
}
die() { printf 'Sentinel installer: %s\n' "$*" >&2; exit 1; }
fetch() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120 --max-filesize 134217728 --retry 2 "$@"; }
cleanup() { [ -z "${staged:-}" ] || rm -f "$staged"; [ -z "${work:-}" ] || rm -rf "$work"; }
# A function prevents execution of a partially downloaded installer body.
main "$@"
