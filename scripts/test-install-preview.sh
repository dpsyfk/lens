#!/bin/sh
set -eu

repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/lens-preview-installer-test.XXXXXX")"
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM

platform="${LENS_PREVIEW_TEST_PLATFORM:-$(uname -s):$(uname -m)}"
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
        echo "unsupported installer-test host" >&2
        exit 1
        ;;
esac

version="0.1.0-preview.1"
root_name="lens-${version}-${target}"
package_root="$temporary_root/$root_name"
asset_root="$temporary_root/assets"
install_root="$temporary_root/installed"
mkdir -p "$package_root" "$asset_root"
printf '#!/bin/sh\necho "lens 0.1.0"\n' > "$package_root/lens"
chmod +x "$package_root/lens"

archive_name="${root_name}.${extension}"
if [ "$extension" = "tar.gz" ]; then
    tar -czf "$asset_root/$archive_name" -C "$temporary_root" "$root_name"
else
    (cd "$temporary_root" && zip -qr "$asset_root/$archive_name" "$root_name")
fi

if command -v sha256sum >/dev/null 2>&1; then
    hash="$(sha256sum "$asset_root/$archive_name" | awk '{ print $1 }')"
else
    hash="$(shasum -a 256 "$asset_root/$archive_name" | awk '{ print $1 }')"
fi
printf '%s  %s\n' "$hash" "$archive_name" > "$asset_root/SHA256SUMS"
printf '[{"tag_name":"preview-v%s","draft":false,"prerelease":true}]\n' "$version" > "$temporary_root/releases.json"

LENS_INSTALLER_TESTING=1 \
LENS_PREVIEW_TEST_PLATFORM="$platform" \
LENS_PREVIEW_RELEASES_JSON="$temporary_root/releases.json" \
LENS_PREVIEW_ASSET_ROOT="$asset_root" \
LENS_PREVIEW_INSTALL_DIRECTORY="$install_root" \
sh "$repository_root/install-preview.sh"

test -x "$install_root/lens"
"$install_root/lens" --version | grep -Eq '^lens[[:space:]]+0\.1\.0$'

printf '%064d  %s\n' 0 "$archive_name" > "$asset_root/SHA256SUMS"
if LENS_INSTALLER_TESTING=1 \
    LENS_PREVIEW_TEST_PLATFORM="$platform" \
    LENS_PREVIEW_RELEASES_JSON="$temporary_root/releases.json" \
    LENS_PREVIEW_ASSET_ROOT="$asset_root" \
    LENS_PREVIEW_INSTALL_DIRECTORY="$install_root" \
    sh "$repository_root/install-preview.sh" 2>/dev/null; then
    echo "preview installer accepted an invalid checksum" >&2
    exit 1
fi

echo "Unix preview installer smoke test passed"
