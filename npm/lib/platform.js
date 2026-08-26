'use strict';

/**
 * Pure platform-mapping helpers for the vaultx-cli npm installer.
 *
 * This module intentionally contains no secret-management logic and no I/O:
 * every function here is deterministic over its arguments so the artifact
 * selection rules can be unit tested without touching the network or disk.
 *
 * There is no telemetry of any kind in this package.
 */

/** Map of `${process.platform}-${process.arch}` -> release asset name. */
const SUPPORTED_ARTIFACTS = Object.freeze({
  'linux-x64': 'vaultx-linux-x86_64',
  'linux-arm64': 'vaultx-linux-aarch64',
  'darwin-x64': 'vaultx-darwin-x86_64',
  'darwin-arm64': 'vaultx-darwin-aarch64',
  'win32-x64': 'vaultx-windows-x86_64.exe',
});

/**
 * Canonical GitHub repository ("owner/name") releases are downloaded from.
 * Forks override this with the VAULTX_CLI_REPOSITORY environment variable.
 */
const DEFAULT_REPOSITORY = 'Dijo-404/vaultx-cli';

/** Error thrown when the running OS/arch combination has no release asset. */
class UnsupportedPlatformError extends Error {
  /**
   * @param {string} platform e.g. "freebsd"
   * @param {string} arch e.g. "arm64"
   */
  constructor(platform, arch) {
    const key = `${platform}-${arch}`;
    super(
      `vaultx-cli has no prebuilt binary for platform "${key}".\n` +
        'Prebuilt binaries are published for:\n' +
        Object.entries(SUPPORTED_ARTIFACTS)
          .map(([k, v]) => `  ${k} -> ${v}`)
          .join('\n') +
        '\nInstall Rust and build from source instead:' +
        ' cargo install --path crates/vaultx-cli'
    );
    this.name = 'UnsupportedPlatformError';
    this.platform = platform;
    this.arch = arch;
  }
}

/**
 * @returns {string[]} sorted list of supported "platform-arch" keys
 */
function supportedPlatformKeys() {
  return Object.keys(SUPPORTED_ARTIFACTS).sort();
}

/**
 * Resolve the release asset name for a platform/arch pair.
 *
 * @param {string} platform Node process.platform value
 * @param {string} arch Node process.arch value
 * @returns {string} release asset name
 * @throws {UnsupportedPlatformError} when the combination is unsupported
 */
function artifactNameFor(platform, arch) {
  const artifact = SUPPORTED_ARTIFACTS[`${platform}-${arch}`];
  if (!artifact) {
    throw new UnsupportedPlatformError(platform, arch);
  }
  return artifact;
}

/**
 * Resolve the repository override for forks.
 *
 * @param {NodeJS.ProcessEnv|Record<string,string|undefined>} env
 * @returns {string} "owner/name"
 */
function repositoryFromEnv(env) {
  const override = env && env.VAULTX_CLI_REPOSITORY;
  if (typeof override === 'string' && /^[^/\s]+\/[^/\s]+$/.test(override.trim())) {
    return override.trim();
  }
  return DEFAULT_REPOSITORY;
}

/**
 * Build the release download URL for an artifact.
 *
 * @param {{repository: string, version: string, artifactName: string}} opts
 * @returns {string} absolute HTTPS URL
 */
function downloadUrlFor({ repository, version, artifactName }) {
  return `https://github.com/${repository}/releases/download/v${version}/${artifactName}`;
}

/**
 * Strict lowercase-hex SHA-256 digest check.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isSha256Hex(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

/**
 * Look up the expected digest for an artifact. Fails closed: an artifact
 * without a published checksum must never be executed.
 *
 * @param {Record<string, string>} checksums artifact name -> sha256 hex
 * @param {string} artifactName
 * @returns {string} lowercase hex sha256
 * @throws {Error} when no well-formed checksum exists for the artifact
 */
function expectedChecksumFor(checksums, artifactName) {
  const digest = checksums[artifactName];
  if (!isSha256Hex(digest)) {
    throw new Error(
      `Refusing to install "${artifactName}": no published SHA-256 checksum ` +
        'is embedded in this package. This usually means the npm package was ' +
        'published before its release artifacts; reinstall from an official release.'
    );
  }
  return digest;
}

module.exports = {
  SUPPORTED_ARTIFACTS,
  DEFAULT_REPOSITORY,
  UnsupportedPlatformError,
  supportedPlatformKeys,
  artifactNameFor,
  repositoryFromEnv,
  downloadUrlFor,
  isSha256Hex,
  expectedChecksumFor,
};
