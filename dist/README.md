# Release distribution

Releases are cut by pushing a tag `v<version>` (e.g. `v0.1.0`). The
`release` job in `.github/workflows/ci.yml` builds the binary crate for
five targets and publishes the artifacts to the GitHub release:

    vaultx-linux-x86_64
    vaultx-linux-aarch64
    vaultx-darwin-x86_64
    vaultx-darwin-aarch64
    vaultx-windows-x86_64.exe

## Integrity metadata

Every release attaches a single `SHA256SUMS` file listing one
`<sha256>  <artifact-name>` line per artifact (standard `sha256sum -c`
format). The checksums file is generated in CI from the freshly built
binaries; binaries are stripped before hashing.

## Verifying an artifact

```sh
sha256sum -c <(grep 'vaultx-linux-x86_64$' SHA256SUMS)
```

or compare against `npm/checksums.json`, which embeds the same digests.

## npm installer

The `npm/` directory ships the `vaultx-cli` installer package. Its
postinstall step detects platform/architecture, downloads the matching
release artifact, verifies its SHA-256 against the embedded checksum map
*before* marking it executable, and errors clearly on unsupported
platforms. The JavaScript installer contains no secret-management
implementation; set `VAULTX_RELEASES_BASE` to override the download
base URL for forks or air-gapped mirrors.
