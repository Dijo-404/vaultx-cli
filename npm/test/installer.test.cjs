'use strict';

/**
 * Unit tests for the pure pieces of the vaultx-cli npm installer.
 * Run from the repository root: node --test npm/test/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const platform = require('../lib/platform.js');
const embed = require('../scripts/embed-checksums.js');

test('maps supported platforms to release artifact names', () => {
  assert.equal(platform.artifactNameFor('linux', 'x64'), 'vaultx-linux-x86_64');
  assert.equal(platform.artifactNameFor('linux', 'arm64'), 'vaultx-linux-aarch64');
  assert.equal(platform.artifactNameFor('darwin', 'x64'), 'vaultx-darwin-x86_64');
  assert.equal(platform.artifactNameFor('darwin', 'arm64'), 'vaultx-darwin-aarch64');
  assert.equal(platform.artifactNameFor('win32', 'x64'), 'vaultx-windows-x86_64.exe');
});

test('rejects unsupported platforms with an actionable error', () => {
  for (const [plat, arch] of [
    ['freebsd', 'x64'],
    ['sunos', 'x64'],
    ['win32', 'arm64'],
    ['linux', 'riscv64'],
    ['darwin', 'ppc64'],
  ]) {
    assert.throws(
      () => platform.artifactNameFor(plat, arch),
      (err) => {
        assert.ok(err instanceof platform.UnsupportedPlatformError);
        assert.equal(err.name, 'UnsupportedPlatformError');
        assert.match(err.message, new RegExp(`${plat}-${arch}`));
        // Error must enumerate what *is* supported so users can self-serve.
        assert.match(err.message, /vaultx-linux-x86_64/);
        return true;
      },
      `${plat}-${arch} should be unsupported`
    );
  }
});

test('supportedPlatformKeys lists exactly the five release artifacts', () => {
  assert.deepEqual(platform.supportedPlatformKeys(), [
    'darwin-arm64',
    'darwin-x64',
    'linux-arm64',
    'linux-x64',
    'win32-x64',
  ]);
});

test('builds GitHub release download URLs', () => {
  assert.equal(
    platform.downloadUrlFor({
      repository: 'acme/vaultx-cli',
      version: '1.2.3',
      artifactName: 'vaultx-linux-aarch64',
    }),
    'https://github.com/acme/vaultx-cli/releases/download/v1.2.3/vaultx-linux-aarch64'
  );
});

test('repository override accepts only owner/name slugs', () => {
  assert.equal(platform.repositoryFromEnv({ VAULTX_CLI_REPOSITORY: ' myfork/vaultx-cli ' }), 'myfork/vaultx-cli');
  assert.equal(platform.repositoryFromEnv({ VAULTX_CLI_REPOSITORY: 'not-a-slug' }), platform.DEFAULT_REPOSITORY);
  assert.equal(platform.repositoryFromEnv({}), platform.DEFAULT_REPOSITORY);
  assert.equal(platform.repositoryFromEnv(undefined), platform.DEFAULT_REPOSITORY);
});

test('sha256 hex validation is strict', () => {
  const valid = 'a'.repeat(64);
  assert.equal(platform.isSha256Hex(valid), true);
  assert.equal(platform.isSha256Hex(valid.toUpperCase()), false, 'must be lowercase');
  assert.equal(platform.isSha256Hex('a'.repeat(63)), false, 'wrong length');
  assert.equal(platform.isSha256Hex(`${'a'.repeat(63)}g`), false, 'non-hex char');
  assert.equal(platform.isSha256Hex(null), false);
  assert.equal(platform.isSha256Hex(42), false);
});

test('checksum lookup fails closed when digest is absent or malformed', () => {
  const checksums = {
    'vaultx-linux-x86_64': 'b'.repeat(64),
    'vaultx-darwin-x86_64': 'not-a-digest',
  };
  assert.equal(platform.expectedChecksumFor(checksums, 'vaultx-linux-x86_64'), 'b'.repeat(64));
  for (const artifact of ['vaultx-darwin-x86_64', 'vaultx-windows-x86_64.exe']) {
    assert.throws(
      () => platform.expectedChecksumFor(checksums, artifact),
      /Refusing to install/,
      `${artifact} must not install without a published checksum`
    );
  }
});

test('embedded checksums.json is well-formed', () => {
  const raw = fs.readFileSync(path.join(__dirname, '..', 'checksums.json'), 'utf8');
  const parsed = JSON.parse(raw);
  assert.equal(parsed.schema, 1);
  assert.equal(typeof parsed.artifacts, 'object');
  for (const digest of Object.values(parsed.artifacts)) {
    assert.match(digest, /^[0-9a-f]{64}$/);
  }
});

test('parseSha256Sums handles sha256sum output formats', () => {
  const { entries, errors } = embed.parseSha256Sums(
    `abc123${'0'.repeat(58)}  vaultx-linux-x86_64\n` +
      `def456${'0'.repeat(58)} *vaultx-windows-x86_64.exe\n` +
      '\n'
  );
  assert.deepEqual(errors, []);
  assert.equal(entries['vaultx-linux-x86_64'], `abc123${'0'.repeat(58)}`);
  assert.equal(entries['vaultx-windows-x86_64.exe'], `def456${'0'.repeat(58)}`);
});

test('parseSha256Sums rejects malformed lines instead of guessing', () => {
  const { errors } = embed.parseSha256Sums('tooshort vaultx-linux-x86_64');
  assert.equal(errors.length, 1);
  assert.match(errors[0], /line 1/);
});

test('selectArtifacts keeps only official release assets and reports gaps', () => {
  const good = '1'.repeat(64);
  const { artifacts, ignored, missing } = embed.selectArtifacts({
    'vaultx-linux-x86_64': good,
    'some-other-binary': good,
  });
  assert.deepEqual(Object.keys(artifacts), ['vaultx-linux-x86_64']);
  assert.deepEqual(ignored, ['some-other-binary']);
  assert.ok(missing.includes('vaultx-windows-x86_64.exe'));
});
