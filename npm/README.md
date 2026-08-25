# vaultx-cli

Installer package for the [vaultx](https://github.com/vaultx-cli/vaultx-cli)
native CLI. Running `npm install -g vaultx-cli` (or using it as a
dependency) downloads the prebuilt `vaultx` binary for your platform from
GitHub Releases, verifies its SHA-256 digest against the checksum map
embedded in this package, and exposes the `vaultx` executable.

Supported platforms:

| platform    | artifact                   |
| ----------- | -------------------------- |
| linux-x64   | `vaultx-linux-x86_64`      |
| linux-arm64 | `vaultx-linux-aarch64`     |
| darwin-x64  | `vaultx-darwin-x86_64`     |
| darwin-arm64| `vaultx-darwin-aarch64`    |
| win32-x64   | `vaultx-windows-x86_64.exe`|

Anything else fails with a clear unsupported-platform error and build-
from-source instructions.

The installer contains no secret-management implementation and collects
no telemetry. Forks and mirrors can redirect downloads with
`VAULTX_CLI_REPOSITORY=owner/name` and `VAULTX_CACHE_DIR=/path`.

## Maintainers: publishing a release

After the tag build attaches artifacts + `SHA256SUMS` to the GitHub
release, embed the digests before `npm publish`:

```sh
sha256sum dist/* | node scripts/embed-checksums.js
npm publish
```

`embed-checksums.js` refuses incomplete checksum lists — an npm package
whose embedded map is missing any of the five artifacts will fail closed
at install time rather than execute unverified binaries.
