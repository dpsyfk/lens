#!/bin/sh
set -eu

repository="${LENS_PREVIEW_REPOSITORY:-dpsyfk/lens}"
install_directory="${LENS_PREVIEW_INSTALL_DIRECTORY:-$HOME/.local/bin}"
testing="${LENS_INSTALLER_TESTING:-0}"
platform="$(uname -s):$(uname -m)"
if [ "$testing" = "1" ] && [ -n "${LENS_PREVIEW_TEST_PLATFORM:-}" ]; then
    platform="$LENS_PREVIEW_TEST_PLATFORM"
fi

case "$platform" in
    Linux:x86_64)
        target="x86_64-unknown-linux-gnu"
        extension="tar.gz"
        ;;
    Darwin:arm64)
        target="aarch64-apple-darwin"
        extension="zip"
        ;;
    Darwin:x86_64)
        target="x86_64-apple-darwin"
        extension="zip"
        ;;
    *)
        echo "Lens previews currently support Linux x64 and macOS Apple silicon/Intel; this machine reports $(uname -s) $(uname -m)." >&2
        exit 1
        ;;
esac

if [ "$testing" = "1" ]; then
    if [ -z "${LENS_PREVIEW_RELEASES_JSON:-}" ] || [ -z "${LENS_PREVIEW_ASSET_ROOT:-}" ]; then
        echo "Installer testing requires LENS_PREVIEW_RELEASES_JSON and LENS_PREVIEW_ASSET_ROOT." >&2
        exit 1
    fi
    releases="$(cat "$LENS_PREVIEW_RELEASES_JSON")"
else
    releases="$(curl --fail --silent --show-error --location \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        -H 'User-Agent: lens-preview-installer' \
        "https://api.github.com/repos/$repository/releases?per_page=50")"
fi

tag="$(printf '%s' "$releases" |
    grep -Eo '"tag_name"[[:space:]]*:[[:space:]]*"preview-v[0-9]+\.[0-9]+\.[0-9]+-preview\.[0-9]+"' |
    head -n 1 |
    sed -E 's/.*"(preview-v[^"]+)"/\1/')"

if [ -z "$tag" ]; then
    echo "No published Lens preview was found at https://github.com/$repository/releases." >&2
    exit 1
fi

if [ "$testing" = "1" ]; then
    release_detail="$releases"
else
    release_detail="$(curl --fail --silent --show-error --location \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        -H 'User-Agent: lens-preview-installer' \
        "https://api.github.com/repos/$repository/releases/tags/$tag")"
fi
if ! printf '%s' "$release_detail" | grep -Eq '"prerelease"[[:space:]]*:[[:space:]]*true' ||
    ! printf '%s' "$release_detail" | grep -Eq '"draft"[[:space:]]*:[[:space:]]*false'; then
    echo "Refusing $tag because it is not a published prerelease." >&2
    exit 1
fi

version="${tag#preview-v}"
archive_name="lens-${version}-${target}.${extension}"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/lens-preview-install.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
archive_path="$temporary_directory/$archive_name"
checksum_path="$temporary_directory/SHA256SUMS"

if [ "$testing" = "1" ]; then
    cp "$LENS_PREVIEW_ASSET_ROOT/$archive_name" "$archive_path"
    cp "$LENS_PREVIEW_ASSET_ROOT/SHA256SUMS" "$checksum_path"
else
    download_root="https://github.com/$repository/releases/download/$tag"
    curl --fail --silent --show-error --location "$download_root/$archive_name" --output "$archive_path"
    curl --fail --silent --show-error --location "$download_root/SHA256SUMS" --output "$checksum_path"
fi

expected_hash="$(awk -v name="$archive_name" '$2 == name || $2 == "*" name { print tolower($1) }' "$checksum_path")"
if [ -z "$expected_hash" ] || [ "$(printf '%s\n' "$expected_hash" | wc -l | tr -d ' ')" -ne 1 ]; then
    echo "SHA256SUMS must contain exactly one entry for $archive_name." >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    actual_hash="$(sha256sum "$archive_path" | awk '{ print tolower($1) }')"
elif command -v shasum >/dev/null 2>&1; then
    actual_hash="$(shasum -a 256 "$archive_path" | awk '{ print tolower($1) }')"
else
    echo "A SHA-256 tool (sha256sum or shasum) is required." >&2
    exit 1
fi

if [ "$actual_hash" != "$expected_hash" ]; then
    echo "Checksum verification failed for $archive_name." >&2
    exit 1
fi

expanded_directory="$temporary_directory/expanded"
mkdir -p "$expanded_directory"
if [ "$extension" = "tar.gz" ]; then
    tar -xzf "$archive_path" -C "$expanded_directory"
else
    unzip -q "$archive_path" -d "$expanded_directory"
fi

source_binary="$expanded_directory/lens-${version}-${target}/lens"
if [ ! -f "$source_binary" ]; then
    echo "The preview archive does not contain the expected Lens binary." >&2
    exit 1
fi

"$source_binary" --version >/dev/null
mkdir -p "$install_directory"
install -m 0755 "$source_binary" "$install_directory/lens"

echo "Installed unsigned Lens development preview $tag at $install_directory/lens"
echo "Add $install_directory to PATH, then run: lens doctor --check all"
