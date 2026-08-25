#!/usr/bin/env node
'use strict';

/**
 * `vaultx` executable shim installed by npm.
 *
 * npm links this file into node_modules/.bin; the real native binary lives
 * in a platform cache directory (see bin/install.js). If the binary is not
 * cached yet (e.g. postinstall was skipped with --ignore-scripts), this
 * shim downloads and verifies it on demand before exec'ing it.
 *
 * This launcher contains no secret-management implementation and collects
 * no telemetry.
 */

const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const { cachedBinaryPath, ensureBinary, resolveCacheDir } = require('../bin/install.js');

function main() {
  const pkgVersion = require('../package.json').version;
  const cacheDir = resolveCacheDir(process.env, process.platform, require('node:os').homedir());
  const binaryPath = cachedBinaryPath(cacheDir, pkgVersion);

  if (!fs.existsSync(binaryPath)) {
    // Synchronous on-demand install so the child's exit code is ours to forward.
    const { status, error } = spawnSync(
      process.execPath,
      [require.resolve('../bin/install.js')],
      { stdio: 'inherit', env: process.env }
    );
    if (error || status !== 0) {
      console.error(
        `vaultx: failed to fetch the ${pkgVersion} binary. ` +
          'Re-run "npm rebuild vaultx-cli" or reinstall the package.'
      );
      process.exit(status && Number.isInteger(status) ? status : 1);
    }
  }

  const result = spawnSync(binaryPath, process.argv.slice(2), {
    stdio: 'inherit',
    windowsHide: false,
  });

  if (result.error && result.error.code === 'ENOENT') {
    console.error(`vaultx: cached binary vanished from ${binaryPath}; run "npm rebuild vaultx-cli".`);
    process.exit(1);
  }
  if (result.signal) {
    process.kill(process.pid, result.signal);
    return;
  }
  process.exit(result.status === null ? 1 : result.status);
}

main();
