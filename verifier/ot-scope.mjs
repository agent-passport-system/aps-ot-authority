// ot-scope/v1: how the authority-fixture contract's four scope fields sit in an APS
// AuthorityDelegationV1 (agent-passport-system 8.0.1, scope profile aps-hierarchical-v1).
//
// One grant per (building, asset, parameter, operation):
//
//     ot:<building_id>:<asset>:<parameter>:<operation>
//
// The grant is a plain aps-hierarchical-v1 grant, so the SDK's own attenuation check
// (compareAuthority, SCOPE_WIDENING) and coverage rule (scopeGrantCovers) apply to it
// unchanged. v1 of this profile carries no wildcard: every grant is exact, so coverage
// is string equality. The value range is not in the delegation; it is the work order's.

import { isValidScopeGrant } from 'agent-passport-system';

export const PROFILE = 'ot-scope/v1';
export const NAMESPACE = 'ot';
export const FIELDS = ['building_id', 'asset', 'parameter', 'operation'];

// A segment must survive the colon grammar unchanged: non-empty printable ASCII, no
// colon (it would shift every later segment) and no '*' (no wildcards in v1).
const SEGMENT = /^[\x21-\x7e]+$/;

export function segmentProblem(value) {
  if (typeof value !== 'string' || value.length === 0) return 'empty or not a string';
  if (!SEGMENT.test(value)) return 'not printable ASCII';
  if (value.includes(':')) return 'contains ":"';
  if (value.includes('*')) return 'contains "*"';
  return null;
}

/** The one grant a normalized call needs, or throws naming the field that cannot be encoded. */
export function grantForCall(call) {
  for (const f of FIELDS) {
    const p = segmentProblem(call?.[f]);
    if (p) throw new Error(`${f} ${p}`);
  }
  const grant = [NAMESPACE, ...FIELDS.map(f => call[f])].join(':');
  if (!isValidScopeGrant(grant)) throw new Error('not a valid aps-hierarchical-v1 grant');
  return grant;
}

/** The contract's scope object ({building_id, assets[], parameters[], operations[]}) as
 *  canonical grants: the cross product, sorted and unique, as the SDK requires. */
export function grantsForScope(scope) {
  const out = new Set();
  for (const asset of scope.assets)
    for (const parameter of scope.parameters)
      for (const operation of scope.operations)
        out.add(grantForCall({ building_id: scope.building_id, asset, parameter, operation }));
  return [...out].sort();
}

export function isExactGrant(grant) {
  return typeof grant === 'string' && !grant.includes('*');
}

/** Contract time "YYYY-MM-DDTHH:MM:SSZ" to the SDK's canonical UTC milliseconds. */
export function toApsTime(t) {
  if (typeof t !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(t))
    throw new Error(`decision_time is not YYYY-MM-DDTHH:MM:SSZ: ${JSON.stringify(t)}`);
  return t.slice(0, -1) + '.000Z';
}

export function b64urlToHex(s) {
  return Buffer.from(s, 'base64url').toString('hex');
}

export function hexToB64url(h) {
  return Buffer.from(h, 'hex').toString('base64url');
}
