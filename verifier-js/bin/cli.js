#!/usr/bin/env node
'use strict';

// trustlayer-verify <bundle.json>
//
// Independently re-checks an exported TrustLayer evidence bundle, offline.
// Exit code: 0 = every offline check passed, 1 = a check failed,
// 2 = usage / unreadable input.

const { readFileSync } = require('node:fs');
const { verifyBundle } = require('..');

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

function main(argv) {
  const path = argv[2];
  if (!path || path === '-h' || path === '--help') {
    process.stderr.write('usage: trustlayer-verify <bundle.json>\n');
    return path ? 0 : 2;
  }

  let bundle;
  try {
    bundle = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    process.stderr.write(`cannot read/parse ${path}: ${err.message}\n`);
    return 2;
  }

  const report = verifyBundle(bundle);
  print(path, report);
  return report.verified ? 0 : 1;
}

const MARK = { ok: `${GREEN}✓${RESET}`, failed: `${RED}✗${RESET}`, not_applicable: `${DIM}–${RESET}` };

function print(path, report) {
  const out = [];
  out.push(`${BOLD}TrustLayer evidence — offline verification${RESET}`);
  out.push(`${DIM}${path}${RESET}`);
  out.push('');

  for (const [name, check] of Object.entries(report.checks)) {
    const mark = MARK[check.status] || '?';
    const detail = check.detail ? ` ${DIM}${check.detail}${RESET}` : ` ${DIM}(not applicable)${RESET}`;
    out.push(`  ${mark} ${name.padEnd(18)}${detail}`);
  }

  if (report.anchors.length) {
    out.push('');
    out.push(`  ${DIM}anchors (re-verify online on their own medium):${RESET}`);
    for (const a of report.anchors) {
      out.push(`    ${DIM}•${RESET} ${a.adapter} ${DIM}— ${a.medium}${RESET}`);
    }
  }

  out.push('');
  out.push(
    report.verified
      ? `${GREEN}${BOLD}VERIFIED${RESET} — every self-contained check passed.`
      : `${RED}${BOLD}NOT VERIFIED${RESET} — one or more checks failed.`,
  );
  process.stdout.write(out.join('\n') + '\n');
}

process.exit(main(process.argv));
