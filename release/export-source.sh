#!/bin/sh
# Create the review tree for the first public release. Repository-local
# history, evidence and operational inventory are intentionally outside it.
set -eu
cd "$(dirname "$0")/.."
[ "$#" -eq 1 ] || { echo 'usage: export-source.sh OUTPUT_DIRECTORY' >&2; exit 1; }
out=$1
mkdir -- "$out"
root=$(pwd -P)
out=$(cd "$out" && pwd -P)
case "$out/" in "$root/"*) rmdir -- "$out"; echo 'choose a directory outside the project' >&2; exit 1 ;; esac
paths='LICENSE NOTICE TRADEMARKS.md SOURCES.md CONTRIBUTING.md licenses README.md README.en.md CHANGELOG.md SECURITY.md install.sh VERSION AGENTS.md .github .dockerignore .editorconfig .gitignore go.mod go.sum third_party.lock.json cmd core internal netplan configs contracts deploy design/locales release docs/assets docs/GETTING_STARTED.md docs/PROTOCOLS.md docs/AGENT_QUICKSTART.md docs/RELEASE_0.1.1.md docs/RELEASE_NOTES_0.1.1.md docs/PUBLIC_PAGE.md docs/USE_CASES.md docs/PUBLICATION.md docs/PUBLICATION_SECURITY_0.1.1.md docs/SBOM.md docs/LICENSE_REVIEW.md docs/LICENSE_ACCEPTANCE_0.1.1.md docs/ACCEPTANCE_0.1.1.md docs/SCREENSHOTS.md docs/screenshots tests/transport/federation_e2e.sh tests/transport/topology.sh tests/transport/fileserver.go'
if [ -n "$(find $paths -type l -print)" ]; then
    echo 'symlinks are forbidden in the release export' >&2
    exit 1
fi
COPYFILE_DISABLE=1 tar --no-xattrs --no-acls -cf - $paths | (cd "$out" && tar -xf -)
