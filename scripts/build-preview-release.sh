#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "$script_dir/.." && pwd)"
cd "$repository_root"

version="$(tr -d '\r\n' < VERSION)"
if [[ ! "$version" =~ ^0\.[0-9]+\.[0-9]+-preview\.[0-9]+$ ]]; then
  printf 'VERSION is not an allowed security-preview version: %s\n' "$version" >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  printf 'Refusing to build release artifacts from a dirty worktree.\n' >&2
  exit 1
fi

commit="$(git rev-parse --verify HEAD)"
tag="v$version"
output_dir="${1:-$repository_root/dist/$tag}"
if [[ -e "$output_dir" ]]; then
  printf 'Release output already exists: %s\n' "$output_dir" >&2
  exit 1
fi
mkdir -p "$output_dir"

targets=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "windows amd64"
)
artifacts=()
for target in "${targets[@]}"; do
  read -r target_os target_arch <<< "$target"
  suffix=""
  if [[ "$target_os" == "windows" ]]; then
    suffix=".exe"
  fi
  filename="propagare-node_${version}_${target_os}_${target_arch}${suffix}"
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -buildid= -X github.com/MacMax-B/propagare/internal/releaseinfo.Version=$version -X github.com/MacMax-B/propagare/internal/releaseinfo.Commit=$commit" \
    -o "$output_dir/$filename" \
    ./cmd/propagare-node
  artifacts+=("$filename")
done

go list -m all > "$output_dir/THIRD_PARTY-MODULES.txt"
{
  printf 'Version: %s\n' "$version"
  printf 'Commit: %s\n' "$commit"
  printf 'Go: %s\n' "$(go env GOVERSION)"
  printf 'CGO: disabled\n'
} > "$output_dir/BUILDINFO.txt"
cp LICENSE SECURITY.md "$output_dir/"
cp "docs/RELEASE-NOTES-$tag.md" "$output_dir/RELEASE-NOTES.md"
artifacts+=("BUILDINFO.txt" "LICENSE" "RELEASE-NOTES.md" "SECURITY.md" "THIRD_PARTY-MODULES.txt")

(
  cd "$output_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${artifacts[@]}" > SHA256SUMS
  else
    shasum -a 256 "${artifacts[@]}" > SHA256SUMS
  fi
)

printf 'Built %s in %s\n' "$tag" "$output_dir"
