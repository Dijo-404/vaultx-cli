#!/usr/bin/env node
'use strict';

/**
 * Embed release checksums into the npm package.
 *
 * Usage:
 *   node scripts/embed-checksums.js path/to/SHA256SUMS
 *   sha256sum dist/* | node scripts/embed-checksums.js
 *
 * Parses a `sha256sum`-style checksum list, keeps only the five official
 * vaultx release artifacts, and rewrites npm/checksums.json. Run this after
 * cutting a GitHub release and before `npm publish` so the installer can
 * verify downloads (plan §40).
 */

const fs = require('node:fs');
const path = require('node:path');
const { isSha256Hex, SUPPORTED_ARTIFACTS } = require('../lib/platform.js');

/**
 * Parse `sha256sum` output ("digest  filename" or "digest *filename").
 *
 * @param {string} text raw SHA256SUMS content
 * @returns {{entries: Record<string,string>, errors: string[]}}
 */
function parseSha256Sums(text) {
  const entries = {};
  const errors = [];
  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    const match = /^([0-9a-fA-F]{64})[ \t]+\*?(.+)$/.exec(line);
    if (!match) {
      errors.push(`line ${index + 1}: not a valid sha256sum entry: "${rawLine}"`);
      continue;
    }
    const [, digest, name] = match;
    entries[name] = digest.toLowerCase();
  }
  return { entries, errors };
}

/**
 * Build the artifacts map restricted to known release assets.
 *
 * @param {Record<string,string>} entries parsed sha256sum entries
 * @returns {{artifacts: Record<string,string>, ignored: string[], missing: string[]}}
 */
function selectArtifacts(entries) {
  const known = new Set(Object.values(SUPPORTED_ARTIFACTS));
  const artifacts = {};
  const ignored = [];
  for (const [name, digest] of Object.entries(entries)) {
    if (known.has(name) && isSha256Hex(digest)) {
      artifacts[name] = digest;
    } else {
      ignored.push(name);
    }
  }
  const missing = [...known].filter((name) => !(name in artifacts));
  return { artifacts, ignored, missing };
}

function main() {
  const inputPath = process.argv[2];
  const text = inputPath ? fs.readFileSync(inputPath, 'utf8') : fs.readFileSync(0, 'utf8');

  const { entries, errors } = parseSha256Sums(text);
  for (const message of errors) {
    console.error(`error: ${message}`);
  }
  if (errors.length > 0) {
    process.exit(1);
  }

  const { artifacts, ignored, missing } = selectArtifacts(entries);
  for (const name of ignored) {
    console.warn(`warning: ignoring non-release artifact "${name}"`);
  }
  if (missing.length > 0) {
    console.error(
      `error: SHA256SUMS is incomplete; missing release artifacts:\n  ${missing.join('\n  ')}`
    );
    process.exit(1);
  }

  const outFile = path.join(__dirname, '..', 'checksums.json');
  fs.writeFileSync(outFile, `${JSON.stringify({ schema: 1, artifacts }, null, 2)}\n`);
  console.log(`wrote ${Object.keys(artifacts).length} checksums to ${outFile}`);
}

module.exports = { parseSha256Sums, selectArtifacts };

if (require.main === module) {
  main();
}
