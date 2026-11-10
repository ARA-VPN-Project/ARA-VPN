# Third-party licensing materials

These files preserve upstream license and attribution texts. They are not
relicensed under ARA VPN's AGPL. File locations retain the module path and
version or the pinned native source revision so that different versions are
not confused.

- `INVENTORY.json`: actual modules and build settings from release binary Go
  metadata; exact source checksums and binary SHA-256 values.
- `NATIVE-SOURCES.json`: native code nested below Go dependencies, with exact
  source revision and release asset hash.
- `third-party/`: original upstream notices, including Go standard library and
  Chromium/NaiveProxy notices.
- `SING-BOX-LICENSE`: upstream sing-box copyright and license notice, including
  its name/association provision.
- `GPL-3.0.txt`: full GNU GPL v3 text for the separately supplied engine.

See the top-level SOURCES.md for release source assets and redistribution.
