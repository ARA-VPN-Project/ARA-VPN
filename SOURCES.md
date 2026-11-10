# Corresponding source for ARA VPN 0.1.1

ARA VPN is licensed under AGPL-3.0-or-later. The separately supplied sing-box
engine remains under its upstream license, GPL-3.0-or-later. Third-party
licenses and notices are preserved, not replaced by ARA's license.

Every public binary release must provide the following downloadable assets
alongside the binaries, at no extra charge:

- `ARA-VPN-0.1.1-source.tar.gz`: ARA source, build scripts, installation scripts,
  license texts, notices, dependency inventory and public instructions.
- `THIRD-PARTY-SOURCES.tar.gz`: exact Go module source archives, including the
  pinned engine, and the source distributions of the two recorded Go toolchains.
- Any additional non-Go source archives listed in `licenses/NATIVE-SOURCES.json`.
  Go module archives containing prebuilt native libraries alone are not their
  corresponding source.
- `RELEASE-SHA256SUMS`: checksums for all published assets.

`licenses/INVENTORY.json` records the union of embedded Go build information in
all release Debian binaries, exact module versions, h1 checksums, SHA-256 hashes
of source ZIPs, build flags and original notice paths. It is more precise than
the historical hand-maintained dependency list. Source ZIPs use Go's standard
module format and are verified against the embedded h1 values where present.
The main engine module has no embedded h1; its downloaded source digest is
recorded explicitly rather than represented as a signed upstream attestation.

To refresh the collection, run `release/prepare-licenses.py --help`. The script
reads Debian archives without installing or executing their payloads. It does
not upgrade any dependency. Preserve the exact source archives with each release;
a link to a moving branch or an unpinned latest version is not a substitute.

Build ARA on Debian using the pinned Go toolchain and
`deploy/debian/build-deb.sh`; supply the reviewed `ARA_SINGBOX` binary and its
locked `ARA_SINGBOX_SHA256`, and select the target with `ARA_ARCH`. The engine's
own source and build information are included separately; original source
build instructions and required submodules must be preserved for native parts.
Reproducibility of an upstream native binary is not claimed solely from a hash.

Public repository: https://github.com/ARA-VPN-Project/ARA-VPN
Release assets: https://github.com/ARA-VPN-Project/ARA-VPN/releases/tag/v0.1.1
Source and binary downloads must remain available together. Validate
unauthenticated downloads after publishing each release.

If you modify the program and operate a version supporting remote interaction,
follow AGPL section 13: prominently offer corresponding source to its remote
users through an appropriate interface. A neutral public landing page need not
expose administrative addresses, credentials or customer data. Public source
archives must never contain those secrets.
