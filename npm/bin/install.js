'use strict';

/**
 * Postinstall downloader for the vaultx-cli npm package.
 *
 * Downloads the prebuilt `vaultx` binary matching the current platform from
 * GitHub Releases, verifies its SHA-256 digest against the checksum map
 * embedded in this package (npm/checksums.json), and caches it on disk.
 * The installer contains no secret-management implementation and collects
 * no telemetry.
 *
 * Exit codes: 0 on success, 1 on any failure (unsupported platform,
 * network error, checksum mismatch).
 */

const { createHash } = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');
const { timingSafeEqual } = require('node:crypto');

const {
  artifactNameFor,
  repositoryFromEnv,
  downloadUrlFor,
  expectedChecksumFor,
} = require('../lib/platform.js');

const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 60_000;

/**
 * Read the embedded checksum map. Returns {} when the map has not been
 * populated yet; installation then fails closed.
 *
 * @returns {{schema: number, artifacts: Record<string, string>}}
 */
function loadEmbeddedChecksums() {
  const file = path.join(__dirname, '..', 'checksums.json');
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (parsed && parsed.schema === 1 && typeof parsed.artifacts === 'object') {
    return parsed;
  }
  return { schema: 1, artifacts: {} };
}

/**
 * Resolve the cache directory for downloaded binaries.
 * Precedence: $VAULTX_CACHE_DIR > XDG_CACHE_HOME/vaultx-cli (unix) >
 * %LOCALAPPDATA%\vaultx-cli (windows) > ~/.cache/vaultx-cli.
 *
 * @param {NodeJS.ProcessEnv|Record<string,string|undefined>} env
 * @param {string} platform Node process.platform value
 * @param {string} homedir os.homedir() result
 * @returns {string}
 */
function resolveCacheDir(env, platform, homedir) {
  if (env.VAULTX_CACHE_DIR) {
    return env.VAULTX_CACHE_DIR;
  }
  if (platform === 'win32') {
    return path.join(env.LOCALAPPDATA || path.join(homedir, 'AppData', 'Local'), 'vaultx-cli');
  }
  return path.join(env.XDG_CACHE_HOME || path.join(homedir, '.cache'), 'vaultx-cli');
}

/**
 * Path of the cached binary for a given package version.
 *
 * @param {string} cacheDir
 * @param {string} version
 * @returns {string}
 */
function cachedBinaryPath(cacheDir, version) {
  return path.join(cacheDir, `vaultx-${version}${process.platform === 'win32' ? '.exe' : ''}`);
}

/**
 * Constant-time comparison of two hex digests of equal length.
 */
function digestsMatch(actualHex, expectedHex) {
  const a = Buffer.from(actualHex, 'hex');
  const b = Buffer.from(expectedHex, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * GET a URL following HTTPS redirects (GitHub release assets redirect to a
 * CDN). Rejects on non-2xx/non-3xx status or too many redirects.
 *
 * @param {string} url
 * @returns {Promise<import('node:http').IncomingMessage>}
 */
function getWithRedirects(url) {
  return new Promise((resolve, reject) => {
    let remaining = MAX_REDIRECTS;
    const requestOnce = (target) => {
      const req = https.get(target, { timeout: REQUEST_TIMEOUT_MS }, (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          if (remaining-- <= 0) {
            reject(new Error(`Too many redirects downloading ${url}`));
            return;
          }
          requestOnce(new URL(res.headers.location, target).toString());
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`Download failed with HTTP ${res.statusCode} for ${target}`));
          return;
        }
        resolve(res);
      });
      req.on('timeout', () => req.destroy(new Error(`Timed out downloading ${target}`)));
      req.on('error', reject);
    };
    requestOnce(url);
  });
}

/**
 * Stream an HTTP response to a file while hashing it. The file is written to
 * `tmpPath` first so a failed download never leaves a partial binary in place.
 *
 * @param {import('node:http').IncomingMessage} res
 * @param {string} tmpPath
 * @returns {Promise<string>} lowercase hex sha256 of the payload
 */
function streamToTmpFile(res, tmpPath) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const out = fs.createWriteStream(tmpPath, { mode: 0o700 });
    res.on('data', (chunk) => hash.update(chunk));
    res.on('error', reject);
    out.on('error', reject);
    out.on('finish', () => resolve(hash.digest('hex')));
    res.pipe(out);
  });
}

/**
 * Download + verify + cache the binary for the current platform.
 *
 * @param {{pkgVersion: string}} opts
 * @param {NodeJS.ProcessEnv|Record<string,string|undefined>} [env]
 * @returns {Promise<string>} absolute path of the verified cached binary
 */
async function ensureBinary({ pkgVersion }, env = process.env) {
  const artifactName = artifactNameFor(process.platform, process.arch); // throws when unsupported
  const repository = repositoryFromEnv(env);
  const url = downloadUrlFor({ repository, version: pkgVersion, artifactName });
  const expectedDigest = expectedChecksumFor(loadEmbeddedChecksums().artifacts, artifactName);

  const cacheDir = resolveCacheDir(env, process.platform, os.homedir());
  fs.mkdirSync(cacheDir, { recursive: true });

  const finalPath = cachedBinaryPath(cacheDir, pkgVersion);
  if (fs.existsSync(finalPath)) {
    return finalPath; // idempotent reinstall/upgrade path
  }

  const tmpPath = `${finalPath}.tmp-${process.pid}`;
  try {
    const res = await getWithRedirects(url);
    const actualDigest = await streamToTmpFile(res, tmpPath);
    if (!digestsMatch(actualDigest, expectedDigest)) {
      throw new Error(
        `Checksum mismatch for ${artifactName}: expected ${expectedDigest}, got ${actualDigest}. ` +
          'The downloaded file was discarded and nothing was executed.'
      );
    }
    if (process.platform !== 'win32') {
      fs.chmodSync(tmpPath, 0o755);
    }
    fs.renameSync(tmpPath, finalPath);
    return finalPath;
  } finally {
    if (fs.existsSync(tmpPath)) {
      fs.rmSync(tmpPath, { force: true });
    }
  }
}

module.exports = {
  ensureBinary,
  loadEmbeddedChecksums,
  resolveCacheDir,
  cachedBinaryPath,
};

/* istanbul ignore next */
if (require.main === module) {
  const pkgVersion = require('../package.json').version;
  ensureBinary({ pkgVersion })
    .then((binaryPath) => {
      console.log(`vaultx ${pkgVersion} installed at ${binaryPath}`);
    })
    .catch((err) => {
      console.error(`vaultx-cli postinstall failed: ${err.message}`);
      console.error('The vaultx executable was NOT installed.');
      process.exit(1);
    });
}
