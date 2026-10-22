#!/bin/bash
# Builds gecko and packages it with the assembler tools for a GitHub release
# Usage: ./build-release.sh 6.0.0
set -euo pipefail

cd "$(dirname "$0")"

version="${1:-}"
if [[ ! "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "Usage: $0 <version>, for example: $0 6.0.0" >&2
  exit 1
fi
version="v${version#v}"

# The binary records the commit it was built from and whether the tree had changes, so only build
# from a clean tree. release/ is ignored by git so the build output doesn't count as a change
if [ -n "$(git status --porcelain)" ]; then
  echo "The working tree has changes. Commit or remove them first:" >&2
  git status --short >&2
  exit 1
fi

sevenzip="$(command -v 7z || command -v 7zz || command -v 7za || true)"
if [ -z "$sevenzip" ] && [ -x "/c/Program Files/7-Zip/7z.exe" ]; then
  sevenzip="/c/Program Files/7-Zip/7z.exe"
fi
if [ -z "$sevenzip" ]; then
  echo "Couldn't find 7-Zip. Install it or add it to your PATH" >&2
  exit 1
fi

# The go.work in the folder above doesn't include this module
export GOWORK=off

go vet ./...
go test ./...

rm -rf release
mkdir release

# The bundled assembler tools are Windows binaries so the release is too. -trimpath keeps local
# folder paths out of the binary
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o release/gecko.exe .
cp powerpc-eabi-as.exe powerpc-eabi-objcopy.exe release/

if go version -m release/gecko.exe | grep -q "vcs.modified=true"; then
  echo "The build was marked as having uncommitted changes, not packaging it" >&2
  exit 1
fi

archive="gecko-tools-$version.7z"
(cd release && "$sevenzip" a -t7z "$archive" gecko.exe powerpc-eabi-as.exe powerpc-eabi-objcopy.exe > /dev/null)

commit="$(git rev-parse --short HEAD)"
echo "Built release/$archive from commit $commit"
if [ -z "$(git branch -r --contains HEAD)" ]; then
  echo "Commit $commit isn't on the remote yet. Push it before creating the $version release"
else
  echo "Create the $version release from commit $commit"
fi
