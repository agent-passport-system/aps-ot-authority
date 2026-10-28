#!/usr/bin/env node
// APS delegation verifier for the autonomous-ot-control authority_fixture harness.
//
//     node verify.mjs run --fixtures <set dir> --out <result.json>
//
// Per case it decides only the delegation side of the contract
// (docs/federation/authority-fixture-contract.md in darklordVirtual/autonomous-ot-control):
// the chain is valid at the call's decision_time and its leaf grants the call's building,
// asset, parameter and operation. It never reads the value, the unit or the work order.
//
// The decision is the SDK's own: selectChainForAction (agent-passport-system 8.0.1) with
// one held chain and one required grant. That function runs verifyAuthorityDelegationChain
// (schema, delegation_id, signatures, root trust, parent links, continuity, the seven-facet
// attenuation check, time window, revocation) and then requires the leaf to cover the grant.
// The refusal reason is the SDK's code, passed through unchanged.
//
// Verdicts: pass | refuse. An SDK answer of "undecided" (indeterminate or unsupported) is
// written as verdict "indeterminate", and a crash on one case as "error": the harness
// records both outside pass/refuse, so neither is ever counted as a refusal.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { selectChainForAction, verifyAuthorityDelegationChain } from 'agent-passport-system';
import { PROFILE, grantForCall, isExactGrant, toApsTime, b64urlToHex } from './ot-scope.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const EDGE_ID = 'aps-authority-verifier';
// At bundle time esbuild defines __SDK_VERSION__ from package-lock.json, so the single-file
// edge does not read node_modules. Unbundled runs still read the installed package.
const SDK_VERSION = typeof __SDK_VERSION__ !== 'undefined'
  ? __SDK_VERSION__
  : JSON.parse(readFileSync(join(HERE, 'node_modules/agent-passport-system/package.json'), 'utf8')).version;

// Trust comes from this directory, never from the fixture set under test.
const TRUST = JSON.parse(readFileSync(join(HERE, 'trust.json'), 'utf8'));
const ROOTS = TRUST.root_verification_methods;
const SIGNERS = { ...TRUST.signer_verification_methods, ...ROOTS };

function options(now) {
  return {
    now,
    resolveVerificationKey(issuer, verificationMethod) {
      if (!verificationMethod.startsWith(issuer + '#')) return { outcome: 'not_found' };
      const key = SIGNERS[verificationMethod];
      return key ? b64urlToHex(key) : { outcome: 'not_found' };
    },
    trustRoot: root => Object.hasOwn(ROOTS, root.verification_method) &&
      root.verification_method.startsWith(root.issuer + '#'),
    // The fixture sets carry no revocation evidence. Test policy: every member is active.
    resolveRevocation: () => 'active',
  };
}

export function decide(call, chain) {
  let grant, now;
  try {
    grant = grantForCall(call);
  } catch (e) {
    return { verdict: 'refuse', reason: `ot_call_unencodable: ${e.message}` };
  }
  try {
    now = toApsTime(call.decision_time);
  } catch (e) {
    return { verdict: 'refuse', reason: `ot_decision_time_malformed: ${e.message}` };
  }
  const opts = options(now);
  const sel = selectChainForAction({ held: [{ chain_id: 'presented', chain }], requiredGrants: [grant], options: opts });
  const aps = { required_grant: grant, now, selected: sel.selected };
  if (!sel.selected) {
    const ev = sel.evaluations[0];
    aps.selection_code = sel.code;
    if (!ev) return { verdict: 'refuse', reason: sel.code, aps };
    Object.assign(aps, { evaluation_outcome: ev.outcome, code: ev.code, chain_state: ev.chain_state });
    let detail = '';
    if (ev.chain_state && ev.chain_state !== 'valid') {
      const f = verifyAuthorityDelegationChain(chain, opts).failures[0];
      if (f) detail = `@${f.index ?? '-'}: ${f.message}`;
    } else if (ev.code === 'scope_not_covered') {
      detail = `: leaf does not grant ${grant}`;
    }
    if (ev.outcome === 'undecided') return { verdict: 'indeterminate', reason: `${ev.code}${detail}`, aps };
    return { verdict: 'refuse', reason: `${ev.code}${detail}`, aps };
  }
  // ot-scope/v1 carries no wildcard: coverage must be string equality, on every member.
  for (let i = 0; i < chain.length; i++) {
    const bad = chain[i].authority.scope.grants.find(g => !isExactGrant(g));
    if (bad !== undefined) return { verdict: 'refuse', reason: `ot_wildcard_grant@${i}: ${bad}`, aps };
  }
  aps.code = sel.evaluations[0].code;
  aps.chain_state = sel.result.state;
  return { verdict: 'pass', reason: `${aps.code}: chain valid at ${now}, leaf grants ${grant}`, aps };
}

function run(fixtures, out) {
  const manifest = JSON.parse(readFileSync(join(fixtures, 'manifest.json'), 'utf8'));
  const verdicts = [];
  for (const { case_id } of manifest.cases) {
    let v;
    try {
      const c = JSON.parse(readFileSync(join(fixtures, 'cases', `${case_id}.json`), 'utf8'));
      v = decide(c.call, c.delegation);
    } catch (e) {
      v = { verdict: 'error', reason: `${e?.name ?? 'Error'}: ${e?.message ?? e}` };
    }
    verdicts.push({ case_id, ...v });
  }
  writeFileSync(out, JSON.stringify({
    schema: 'ot-authority-verifier-result/v1', edge_id: EDGE_ID,
    verifier_revision: `agent-passport-system@${SDK_VERSION}; ${PROFILE}`, verdicts,
  }, null, 2) + '\n', 'utf8');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [cmd, ...rest] = process.argv.slice(2);
  const arg = name => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : undefined; };
  if (cmd !== 'run' || !arg('--fixtures') || !arg('--out')) {
    process.stderr.write('usage: verify.mjs run --fixtures <set dir> --out <result.json>\n');
    process.exit(2);
  }
  run(arg('--fixtures'), arg('--out'));
}
