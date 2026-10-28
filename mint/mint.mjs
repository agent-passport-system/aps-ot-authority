#!/usr/bin/env node
// Mint the five issue-#27 cases as APS authority-delegation chains, and the submission
// (ot-authority-submission/v1) the testbed assembles into a sealed set.
//
//     node mint/mint.mjs [--revision <commit>]
//
// Writes submission/aps-1/ and verifier/trust.json. Deterministic: Ed25519 is
// deterministic, every nonce and time is fixed, so a rerun writes the same bytes.
//
// TEST-ONLY KEYS. Each private key is the SHA-256 of a public label, so anyone can sign
// as these identities. They exist so the fixtures are reproducible; never trust them
// anywhere else.

import { createHash } from 'node:crypto';
import { execSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  issueAuthorityDelegation, issueSubAuthorityDelegation, computeAuthorityDelegationId,
  signAuthorityDelegation, publicKeyFromPrivate,
} from 'agent-passport-system';
import { PROFILE, grantsForScope, hexToB64url } from '../verifier/ot-scope.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'submission', 'aps-1');
const KEY_LABEL = 'aeoess APS TEST-ONLY ot-authority delegation key: ';

const sha256hex = s => createHash('sha256').update(s, 'utf8').digest('hex');
const testKey = label => sha256hex(KEY_LABEL + label); // 32-byte Ed25519 seed, hex

function identity(name) {
  const priv = testKey(name);
  return { id: `aps-test:${name}`, vm: `aps-test:${name}#key-1`, priv, pub: publicKeyFromPrivate(priv) };
}

const OWNER = identity('building-owner');
const OPERATOR = identity('operator');
const AGENT = identity('agent');
const BUILDING = 'demo-building-001';
const DAY = '2026-01-15';
const DECISION = `${DAY}T07:00:00Z`;
const T0 = `${DAY}T00:00:00.000Z`;

const scope = assets => ({
  profile: 'aps-hierarchical-v1',
  grants: grantsForScope({ building_id: BUILDING, assets, parameters: ['setpoint_c'], operations: ['set_zone_setpoint'] }),
});

function authority(assets, notAfter, remaining) {
  return {
    scope: scope(assets),
    spend: { mode: 'unbounded' },
    depth: { remaining },
    time: { not_before: T0, not_after: notAfter },
    reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1', required: [] },
    reversibility: { profile: 'aps-tci-v1', ceiling: 'compensable' },
  };
}

function body(parentId, issuer, subject, auth, nonceLabel) {
  return {
    record_type: 'aps:authority-delegation:v1', version: '1.0', parent_delegation_id: parentId,
    issuer: issuer.id, subject: subject.id, verification_method: issuer.vm, issued_at: T0,
    nonce: sha256hex('nonce: ' + nonceLabel).slice(0, 32), authority: auth,
  };
}

// The building owner grants the operator ZONE-01 and ZONE-02 for the whole day.
const root = issueAuthorityDelegation(
  body(null, OWNER, OPERATOR, authority(['ZONE-01', 'ZONE-02'], `${DAY}T23:59:59.000Z`, 1), 'root'),
  OWNER.priv);

const issueOptions = {
  now: T0,
  resolveVerificationKey: (_issuer, vm) => (vm === OWNER.vm ? OWNER.pub : vm === OPERATOR.vm ? OPERATOR.pub : null),
  resolveRevocation: () => 'active',
};

/** The operator's grant to the agent, issued through the SDK, which refuses to widen. */
function leaf(caseId, assets, notAfter) {
  return issueSubAuthorityDelegation(root, body(root.delegation_id, OPERATOR, AGENT, authority(assets, notAfter, 0), caseId),
    OPERATOR.priv, issueOptions);
}

/** A widened leaf, signed directly: issueSubAuthorityDelegation would refuse to mint it. */
function widenedLeaf(caseId, assets, notAfter) {
  const b = body(root.delegation_id, OPERATOR, AGENT, authority(assets, notAfter, 0), caseId);
  const unsigned = { ...b, delegation_id: computeAuthorityDelegationId(b) };
  return { ...unsigned, signature: signAuthorityDelegation(unsigned, OPERATOR.priv) };
}

const LEAF_UNTIL = `${DAY}T18:00:00.000Z`;
const CASES = [
  { case_id: 'af-1-valid', fault: null, value: 20.5, wo: 'pass',
    construction: 'owner grants operator ZONE-01 and ZONE-02; operator grants agent ZONE-01 until 18:00; call ZONE-01 at 07:00, 20.5 degC',
    leaf: () => leaf('af-1-valid', ['ZONE-01'], LEAF_UNTIL) },
  { case_id: 'af-2-widened', fault: 'widened', value: 20.5, wo: 'pass',
    construction: 'operator holds ZONE-01 and ZONE-02 but grants the agent ZONE-01 and ZONE-03 (signed directly; the SDK issuer refuses to widen)',
    leaf: () => widenedLeaf('af-2-widened', ['ZONE-01', 'ZONE-03'], LEAF_UNTIL) },
  { case_id: 'af-3-expired', fault: 'expired', value: 20.5, wo: 'pass',
    construction: "the agent's grant for ZONE-01 ends at 06:00 (not_after, exclusive); the decision time is 07:00",
    leaf: () => leaf('af-3-expired', ['ZONE-01'], `${DAY}T06:00:00.000Z`) },
  { case_id: 'af-4-out-of-scope', fault: 'out_of_scope', value: 20.5, wo: 'pass',
    construction: 'a valid, narrowed chain grants the agent ZONE-02 only; the call is on ZONE-01',
    leaf: () => leaf('af-4-out-of-scope', ['ZONE-02'], LEAF_UNTIL) },
  { case_id: 'af-5-value-out-of-range', fault: null, value: 22.5, wo: 'refuse',
    construction: "valid chain granting ZONE-01; the value 22.5 is outside the work order's 19.0..21.0, which the delegation does not carry",
    leaf: () => leaf('af-5-value-out-of-range', ['ZONE-01'], LEAF_UNTIL) },
];

function revision() {
  const i = process.argv.indexOf('--revision');
  if (i >= 0) return process.argv[i + 1];
  const dirty = execSync('git status --porcelain -- . ":(exclude)submission" ":(exclude)verifier/trust.json" ":(exclude)runs"', { cwd: ROOT, encoding: 'utf8' });
  if (dirty.trim()) throw new Error('uncommitted changes outside submission/: commit first so the revision names what built the set');
  return execSync('git rev-parse HEAD', { cwd: ROOT, encoding: 'utf8' }).trim();
}

const write = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2) + '\n', 'utf8');
const b64 = id => hexToB64url(id.pub);

const rev = revision();
rmSync(OUT, { recursive: true, force: true });
mkdirSync(join(OUT, 'delegations'), { recursive: true });

const cases = CASES.map(c => {
  const chain = [root, c.leaf()];
  const file = `delegations/${c.case_id}.json`;
  write(join(OUT, file), chain);
  return {
    case_id: c.case_id, construction: c.construction, delegation_fault: c.fault, delegation_file: file,
    delegation_id: chain.at(-1).delegation_id,
    call: { asset: 'ZONE-01', value: c.value, decision_time: DECISION },
    expected_work_order: c.wo,
  };
});

write(join(OUT, 'submission.json'), {
  schema: 'ot-authority-submission/v1',
  set_id: 'aps-1',
  source: { project: 'Agent Passport System (aeoess)', repository: 'aeoess/aps-ot-authority (local prototype, not published)', revision: rev },
  delegation_format: 'aps:authority-delegation:v1 (agent-passport-system 8.0.1, npm integrity sha512-g9/AlzqX+L/fKzdsFQICGj59rYnXgeFxZcnmwD8WFNOK8aPSxT8FZEQe/PzGpnpG31xTLeLuMyrInX2B/Id5oA==). '
    + 'Each file is the complete signed chain, a JSON array root to leaf; delegation_id is the leaf\'s. '
    + `Scope: aps-hierarchical-v1 grants in ${PROFILE}, one exact grant ot:<building_id>:<asset>:<parameter>:<operation> per tuple, no wildcards. `
    + 'Validity: authority.time, not_before inclusive, not_after exclusive, UTC milliseconds.',
  scope: 'The five cases of issue #27 as APS authority-delegation chains on the simulated building. Synthetic; TEST-ONLY keys derived from public labels (mint/mint.mjs); no physical control.',
  building_id: BUILDING,
  delegation_root_keys: { [OWNER.vm]: b64(OWNER) },
  delegation_signer_keys: { [OWNER.vm]: b64(OWNER), [OPERATOR.vm]: b64(OPERATOR) },
  cases,
});

write(join(ROOT, 'verifier', 'trust.json'), {
  note: 'TEST-ONLY keys, derived from public labels in mint/mint.mjs. Anyone can sign with them. Never trust them anywhere else.',
  root_verification_methods: { [OWNER.vm]: b64(OWNER) },
  signer_verification_methods: { [OPERATOR.vm]: b64(OPERATOR) },
});

console.log(`submission/aps-1: ${cases.length} cases built at ${rev}`);
for (const c of cases) console.log(`  ${c.case_id}  ${c.delegation_id}`);
