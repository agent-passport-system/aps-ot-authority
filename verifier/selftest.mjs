#!/usr/bin/env node
// Checks of the verifier beyond the five harness cases: window boundaries, tampering,
// unencodable calls, a wildcard grant, a chain without its root. Each line states the
// input, the expected verdict and reason code, and what the verifier answered.
//
//     node verifier/selftest.mjs        (after node mint/mint.mjs)

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { issueAuthorityDelegation, issueSubAuthorityDelegation, canonicalizeJCS, publicKeyFromPrivate } from 'agent-passport-system';
import { decide } from './verify.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const load = id => JSON.parse(readFileSync(join(ROOT, 'submission/aps-1/delegations', `${id}.json`), 'utf8'));
const call = (over = {}) => ({ schema: 'ot-normalized-call/v1', building_id: 'demo-building-001', asset: 'ZONE-01',
  parameter: 'setpoint_c', operation: 'set_zone_setpoint', value: 20.5, unit: 'degC',
  decision_time: '2026-01-15T07:00:00Z', ...over });

const valid = load('af-1-valid');
const tampered = structuredClone(valid);
tampered[1].signature = (tampered[1].signature[0] === '0' ? '1' : '0') + tampered[1].signature.slice(1);
const editedScope = structuredClone(valid);
editedScope[1].authority.scope.grants = ['ot:demo-building-001:ZONE-02:setpoint_c:set_zone_setpoint'];

// A wildcard chain, signed with the same label-derived test keys mint.mjs uses.
const sha = s => createHash('sha256').update(s, 'utf8').digest('hex');
const key = l => sha('aeoess APS TEST-ONLY ot-authority delegation key: ' + l);
const facets = (grants, remaining) => ({ scope: { profile: 'aps-hierarchical-v1', grants }, spend: { mode: 'unbounded' },
  depth: { remaining }, time: { not_before: '2026-01-15T00:00:00.000Z', not_after: '2026-01-15T18:00:00.000Z' },
  reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 }, values: { profile: 'aps-values-identifiers-v1', required: [] },
  reversibility: { profile: 'aps-tci-v1', ceiling: 'compensable' } });
const b = (parent, iss, sub, grants, remaining, n) => ({ record_type: 'aps:authority-delegation:v1', version: '1.0',
  parent_delegation_id: parent, issuer: `aps-test:${iss}`, subject: `aps-test:${sub}`, verification_method: `aps-test:${iss}#key-1`,
  issued_at: '2026-01-15T00:00:00.000Z', nonce: sha('selftest ' + n).slice(0, 32), authority: facets(grants, remaining) });
const wRoot = issueAuthorityDelegation(b(null, 'building-owner', 'operator', ['ot:demo-building-001:*'], 1, 'w-root'), key('building-owner'));
const wLeaf = issueSubAuthorityDelegation(wRoot, b(wRoot.delegation_id, 'operator', 'agent', ['ot:demo-building-001:ZONE-01:*'], 0, 'w-leaf'),
  key('operator'), { now: '2026-01-15T00:00:00.000Z', resolveRevocation: () => 'active',
    resolveVerificationKey: () => publicKeyFromPrivate(key('building-owner')) });

const CHECKS = [
  ['decision at 17:59:59, leaf ends 18:00', valid, call({ decision_time: '2026-01-15T17:59:59Z' }), 'pass', 'scope_covered'],
  ['decision at 18:00:00, not_after exclusive', valid, call({ decision_time: '2026-01-15T18:00:00Z' }), 'refuse', 'EXPIRED'],
  ['decision before not_before', valid, call({ decision_time: '2026-01-14T23:59:59Z' }), 'refuse', 'NOT_YET_VALID'],
  ['leaf signature tampered', tampered, call(), 'refuse', 'SIGNATURE_INVALID'],
  ['leaf scope edited after signing', editedScope, call(), 'refuse', 'ID_MISMATCH'],
  ['leaf presented without its root', [valid[1]], call(), 'refuse', 'ROOT_UNTRUSTED'],
  ['other building', valid, call({ building_id: 'demo-building-002' }), 'refuse', 'scope_not_covered'],
  ['other parameter', valid, call({ parameter: 'mode' }), 'refuse', 'scope_not_covered'],
  ['other operation', valid, call({ operation: 'set_zone_mode' }), 'refuse', 'scope_not_covered'],
  ['asset carrying a colon', valid, call({ asset: 'ZONE-01:setpoint_c' }), 'refuse', 'ot_call_unencodable'],
  ['asset carrying a wildcard', valid, call({ asset: '*' }), 'refuse', 'ot_call_unencodable'],
  ['decision time with fractional seconds', valid, call({ decision_time: '2026-01-15T07:00:00.5Z' }), 'refuse', 'ot_decision_time_malformed'],
  ['wildcard grants, SDK covers the call', [wRoot, wLeaf], call(), 'refuse', 'ot_wildcard_grant'],
  ['value outside any range (not APS\'s check)', valid, call({ value: 99 }), 'pass', 'scope_covered'],
];

let failed = 0;
for (const [name, chain, c, verdict, code] of CHECKS) {
  const got = decide(c, chain);
  const ok = got.verdict === verdict && got.reason.startsWith(code);
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}: expected ${verdict} ${code}; got ${got.verdict} (${got.reason})`);
}
// The SDK's JCS digest of each delegation file, to compare with runner.jcs on the testbed side.
for (const id of ['af-1-valid', 'af-2-widened', 'af-3-expired', 'af-4-out-of-scope', 'af-5-value-out-of-range'])
  console.log(`jcs-sha256 ${id} ${createHash('sha256').update(canonicalizeJCS(load(id)), 'utf8').digest('hex')}`);
console.log(failed ? `${failed} of ${CHECKS.length} checks failed` : `all ${CHECKS.length} checks as expected`);
process.exit(failed ? 1 : 0);
