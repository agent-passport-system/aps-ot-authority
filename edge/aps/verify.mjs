#!/usr/bin/env node
// Bundle: edge/aps/verify.mjs = verifier/verify.mjs + agent-passport-system 8.0.1 (Apache-2.0,
// Copyright 2024-2026 Tymofii Pidlisnyi, LICENSE alongside). No other package is bundled.
// Built with esbuild 0.25.10, see README.md. Source and lockfile: ../../verifier/.
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};

// verifier/node_modules/agent-passport-system/dist/src/crypto/ed25519-admissibility.js
function mod(a) {
  const r = a % P;
  return r < 0n ? r + P : r;
}
function powMod(base, exponent) {
  let result2 = 1n;
  let b = mod(base);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n)
      result2 = mod(result2 * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return result2;
}
function bytesToLittleEndian(bytes) {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--)
    n = n << 8n | BigInt(bytes[i]);
  return n;
}
function decodePoint(bytes) {
  const n = bytesToLittleEndian(bytes);
  const sign2 = n >> 255n & 1n;
  const y = mod(n & LOW_255);
  const yy = mod(y * y);
  const u = mod(yy - 1n);
  const v = mod(D * yy + 1n);
  if (v === 0n)
    return null;
  const v2 = mod(v * v);
  const v3 = mod(v2 * v);
  const v7 = mod(mod(v3 * v3) * v);
  let x = mod(mod(u * v3) * powMod(mod(u * v7), SQRT_EXP));
  const check = mod(v * mod(x * x));
  if (check !== u) {
    if (check === mod(-u))
      x = mod(x * SQRT_M1);
    else
      return null;
  }
  if (x % 2n !== sign2)
    x = mod(P - x);
  return { x, y };
}
function isCanonicalEncoding(bytes, point) {
  const n = bytesToLittleEndian(bytes);
  if ((n & LOW_255) >= P)
    return false;
  if (point.x === 0n && n >> 255n === 1n)
    return false;
  return true;
}
function hasSmallOrder(point) {
  let X = point.x;
  let Y = point.y;
  let Z = 1n;
  for (let i = 0; i < 3; i++) {
    const B = mod((X + Y) * (X + Y));
    const C = mod(X * X);
    const Dd = mod(Y * Y);
    const Ee = mod(-C);
    const F = mod(Ee + Dd);
    const H = mod(Z * Z);
    const J = mod(F - 2n * H);
    X = mod(mod(B - C - Dd) * J);
    Y = mod(F * mod(Ee - Dd));
    Z = mod(F * J);
  }
  if (Z === 0n)
    return true;
  return X === 0n && Y === Z;
}
function isAdmissiblePoint(bytes) {
  if (bytes.length !== 32)
    return false;
  const point = decodePoint(bytes);
  if (point === null)
    return false;
  if (!isCanonicalEncoding(bytes, point))
    return false;
  return !hasSmallOrder(point);
}
function isAdmissibleKeyMaterial(publicKey, signature) {
  if (publicKey.length !== 32 || signature.length !== 64)
    return false;
  return isAdmissiblePoint(publicKey) && isAdmissiblePoint(signature.subarray(0, 32));
}
var P, D, SQRT_M1, LOW_255, SQRT_EXP;
var init_ed25519_admissibility = __esm({
  "verifier/node_modules/agent-passport-system/dist/src/crypto/ed25519-admissibility.js"() {
    P = (1n << 255n) - 19n;
    D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
    SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
    LOW_255 = (1n << 255n) - 1n;
    SQRT_EXP = (P - 5n) / 8n;
  }
});

// verifier/node_modules/agent-passport-system/dist/src/crypto/keys.js
import crypto2 from "node:crypto";
function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`Invalid hex string (length=${hex?.length || 0})`);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}
function verify(message, signatureHex, publicKeyHex) {
  if (typeof publicKeyHex !== "string" || publicKeyHex.length !== 64)
    return false;
  if (typeof signatureHex !== "string" || signatureHex.length !== 128)
    return false;
  try {
    const pubBytes = hexToBytes(publicKeyHex);
    const sigBytes = hexToBytes(signatureHex);
    if (!isAdmissibleKeyMaterial(pubBytes, sigBytes))
      return false;
    const derPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const derKey = Buffer.concat([derPrefix, Buffer.from(pubBytes)]);
    const keyObj = crypto2.createPublicKey({ key: derKey, format: "der", type: "spki" });
    return crypto2.verify(null, Buffer.from(message, "utf8"), keyObj, Buffer.from(sigBytes));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("Invalid key") || msg.includes("asn1") || msg.includes("key length")) {
      console.warn(`[agent-passport] verify(): malformed input \u2014 ${JSON.stringify(msg.slice(0, 200))}`);
    }
    return false;
  }
}
var init_keys = __esm({
  "verifier/node_modules/agent-passport-system/dist/src/crypto/keys.js"() {
    init_ed25519_admissibility();
  }
});

// verifier/node_modules/agent-passport-system/dist/src/core/write-policy.js
function isUnsafeWriteInteger(value) {
  return Number.isFinite(value) && Number.isInteger(value) && Math.abs(value) > MAX_SAFE_WRITE_INTEGER;
}
var MAX_SAFE_WRITE_INTEGER, UNSAFE_INTEGER_CATEGORY, UNSAFE_INTEGER_REASON, UnsafeIntegerError;
var init_write_policy = __esm({
  "verifier/node_modules/agent-passport-system/dist/src/core/write-policy.js"() {
    MAX_SAFE_WRITE_INTEGER = 9007199254740991;
    UNSAFE_INTEGER_CATEGORY = "invalid_number";
    UNSAFE_INTEGER_REASON = "integer_exceeds_interoperable_range";
    UnsafeIntegerError = class extends Error {
      category = UNSAFE_INTEGER_CATEGORY;
      reason = UNSAFE_INTEGER_REASON;
      constructor(path) {
        super(`${path}: integer exceeds the interoperable IEEE 754 range`);
        this.name = "UnsafeIntegerError";
      }
    };
  }
});

// verifier/node_modules/agent-passport-system/dist/src/core/rfc3339.js
var init_rfc3339 = __esm({
  "verifier/node_modules/agent-passport-system/dist/src/core/rfc3339.js"() {
  }
});

// verifier/node_modules/agent-passport-system/dist/src/core/canonical.js
var init_canonical = __esm({
  "verifier/node_modules/agent-passport-system/dist/src/core/canonical.js"() {
    init_write_policy();
    init_rfc3339();
  }
});

// verifier/node_modules/agent-passport-system/dist/src/core/canonical-jcs.js
function assertNoLoneSurrogate(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 55296 && c <= 56319) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next >= 56320 && next <= 57343) {
        i++;
        continue;
      }
      throw new JcsCanonicalizationError("ERR_JCS_LONE_SURROGATE", "canonicalizeJCS: string contains an unpaired UTF-16 high surrogate; a lone surrogate has no valid UTF-8 encoding and RFC 8785 requires rejection");
    }
    if (c >= 56320 && c <= 57343) {
      throw new JcsCanonicalizationError("ERR_JCS_LONE_SURROGATE", "canonicalizeJCS: string contains an unpaired UTF-16 low surrogate; a lone surrogate has no valid UTF-8 encoding and RFC 8785 requires rejection");
    }
  }
}
function canonicalizeJCS(value) {
  assertNoUndefined(value, "$");
  return canonicalizeValue(value);
}
function canonicalizeValue(value, writePath) {
  if (value === null)
    return "null";
  if (writePath !== void 0 && value === void 0) {
    throw new TypeError(`canonicalizeJCS: undefined at ${writePath}`);
  }
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number": {
      if (!isFinite(value))
        throw new Error("JCS does not support Infinity or NaN");
      if (writePath !== void 0 && isUnsafeWriteInteger(value)) {
        throw new UnsafeIntegerError(writePath);
      }
      return JSON.stringify(value);
    }
    case "string":
      assertNoLoneSurrogate(value);
      return JSON.stringify(value);
    case "object": {
      if (value instanceof Date)
        return JSON.stringify(value);
      if (Array.isArray(value)) {
        if (writePath !== void 0) {
          const parts = [];
          for (let i = 0; i < value.length; i++) {
            parts.push(canonicalizeValue(value[i], `${writePath}[${i}]`));
          }
          return "[" + parts.join(",") + "]";
        }
        return "[" + value.map((item) => canonicalizeValue(item)).join(",") + "]";
      }
      const obj = value;
      const keys = Object.keys(obj).sort();
      const pairs = [];
      for (const key of keys) {
        assertNoLoneSurrogate(key);
        const v = obj[key];
        pairs.push(`${JSON.stringify(key)}:${canonicalizeValue(v, writePath === void 0 ? void 0 : `${writePath}.${key}`)}`);
      }
      return "{" + pairs.join(",") + "}";
    }
    default:
      throw new Error(`JCS: unsupported type ${typeof value}`);
  }
}
function assertNoUndefined(value, path) {
  if (value === void 0) {
    throw new TypeError(`canonicalizeJCS: undefined at ${path}`);
  }
  if (value === null || typeof value !== "object")
    return;
  if (value instanceof Date)
    return;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++)
      assertNoUndefined(value[i], `${path}[${i}]`);
    return;
  }
  const obj = value;
  for (const key of Object.keys(obj))
    assertNoUndefined(obj[key], `${path}.${key}`);
}
var JcsCanonicalizationError;
var init_canonical_jcs = __esm({
  "verifier/node_modules/agent-passport-system/dist/src/core/canonical-jcs.js"() {
    init_write_policy();
    JcsCanonicalizationError = class extends Error {
      code;
      /** Stable machine-readable category, shared across the APS SDKs. */
      category = "invalid_unicode";
      /** Specific failure within the category, e.g. 'lone_surrogate'. */
      reason;
      constructor(code, message, reason = "lone_surrogate") {
        super(message);
        this.name = "JcsCanonicalizationError";
        this.code = code;
        this.reason = reason;
      }
    };
  }
});

// verifier/node_modules/agent-passport-system/dist/src/core/did.js
var init_did = __esm({
  "verifier/node_modules/agent-passport-system/dist/src/core/did.js"() {
    init_canonical();
    init_keys();
  }
});

// verifier/node_modules/agent-passport-system/dist/src/v2/mutual-auth/certificate.js
var init_certificate = __esm({
  "verifier/node_modules/agent-passport-system/dist/src/v2/mutual-auth/certificate.js"() {
    init_canonical_jcs();
    init_keys();
  }
});

// verifier/node_modules/agent-passport-system/dist/src/v2/mutual-auth/handshake.js
var init_handshake = __esm({
  "verifier/node_modules/agent-passport-system/dist/src/v2/mutual-auth/handshake.js"() {
    init_canonical_jcs();
    init_keys();
    init_certificate();
  }
});

// verifier/verify.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// verifier/node_modules/agent-passport-system/dist/src/core/passport.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/verification/verify.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/values.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/delegation.js
init_keys();
init_canonical();
init_rfc3339();
init_canonical();
var REVOCATION_CHECK_POLICIES = Object.freeze(["fail_open", "fail_closed", "cache_grace"]);

// verifier/node_modules/agent-passport-system/dist/src/index.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/scope-version.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/action-ref.js
init_canonical();
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/core/external-action-ref.js
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/action-reference/v2.js
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/receipt-core/jcs.js
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/core/idempotency.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/freshness.js
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/attestation.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/index.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/core/completion.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-consent/create.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-consent/sign.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-consent/verify.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/identity-binding/did-aps.js
init_did();

// verifier/node_modules/agent-passport-system/dist/src/core/time.js
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/attribution.js
init_keys();
init_canonical();
var MOVED = "Moved to @aeoess/gateway. See MIGRATION.md#attribution-reports";
var DEFAULT_SCOPE_WEIGHTS = new Proxy({}, {
  get() {
    throw new Error(MOVED);
  }
});

// verifier/node_modules/agent-passport-system/dist/src/core/agora.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/intent.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/coordination.js
init_canonical();
init_rfc3339();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/core/policy.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/decisionReceipt.js
init_keys();
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/core/commerce.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/v2/wallet-binding/bind.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/routing.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/fidelity-probe.js
init_canonical();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/core/did-interop.js
import { isIP, BlockList } from "node:net";
init_did();
var SSRF_BLOCKLIST = new BlockList();
SSRF_BLOCKLIST.addSubnet("127.0.0.0", 8, "ipv4");
SSRF_BLOCKLIST.addSubnet("169.254.0.0", 16, "ipv4");
SSRF_BLOCKLIST.addSubnet("10.0.0.0", 8, "ipv4");
SSRF_BLOCKLIST.addSubnet("172.16.0.0", 12, "ipv4");
SSRF_BLOCKLIST.addSubnet("192.168.0.0", 16, "ipv4");
SSRF_BLOCKLIST.addSubnet("0.0.0.0", 8, "ipv4");
SSRF_BLOCKLIST.addSubnet("::1", 128, "ipv6");
SSRF_BLOCKLIST.addSubnet("fe80::", 10, "ipv6");
SSRF_BLOCKLIST.addSubnet("fc00::", 7, "ipv6");

// verifier/node_modules/agent-passport-system/dist/src/v2/key-resolution/types.js
var DEFAULT_CACHE_POLICY = {
  ttlMs: 5 * 6e4,
  negativeTtlMs: 3e4,
  maxEntries: 256
};

// verifier/node_modules/agent-passport-system/dist/src/v2/key-resolution/resolver.js
init_did();
var AMBIGUOUS = Symbol("kid-ambiguous");

// verifier/node_modules/agent-passport-system/dist/src/core/identity-bridge.js
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/adapters/oauth-id-jag/index.js
init_canonical_jcs();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/reanchor.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/adapters/oauth-id-jag/index.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/adapters/oauth-id-jag/verify.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/core/vc-wrapper.js
init_canonical();
init_rfc3339();
init_keys();
init_did();

// verifier/node_modules/agent-passport-system/dist/src/core/credential-request.js
init_canonical();
init_keys();
init_did();

// verifier/node_modules/agent-passport-system/dist/src/core/gateway-identity.js
init_did();

// verifier/node_modules/agent-passport-system/dist/src/core/principal.js
init_keys();
init_canonical();
init_did();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/entity-verification.js
init_did();

// verifier/node_modules/agent-passport-system/dist/src/core/charter.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/precedent.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/federation.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/oracle-witness.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/reserve.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/governance-consumer.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/governance-block.js
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/aps-txt.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/encrypted-messaging.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/messaging-audit.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/anchor-state.js
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/transactional.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/index.js
init_did();

// verifier/node_modules/agent-passport-system/dist/src/core/key-rotation.js
init_canonical();
init_rfc3339();
init_keys();
init_did();
var DEFAULT_PLANNED_OVERLAP_MS = 24 * 60 * 60 * 1e3;

// verifier/node_modules/agent-passport-system/dist/src/core/vc.js
init_canonical();
init_rfc3339();
init_keys();
init_did();

// verifier/node_modules/agent-passport-system/dist/src/core/trust-adapters.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/core/a2a.js
init_canonical();
init_keys();
init_did();

// verifier/node_modules/agent-passport-system/dist/src/core/reputation-authority.js
init_canonical();
init_rfc3339();
init_keys();
var MAX_SIGMA = 25;
var DEFAULT_PROMOTION_REQUIREMENTS = {
  1: {
    minReceipts: 10,
    minStandardPct: 0.1,
    minComplexPct: 0,
    minDistinctReviewers: 1,
    minDistinctTaskTypes: 2,
    maxFailureRate: 0.3,
    maxInterventionRate: 0.5,
    minTimeInCurrentTier: 0
  },
  2: {
    minReceipts: 50,
    minStandardPct: 0.2,
    minComplexPct: 0.05,
    minDistinctReviewers: 2,
    minDistinctTaskTypes: 3,
    maxFailureRate: 0.15,
    maxInterventionRate: 0.3,
    minTimeInCurrentTier: 7 * 24 * 60 * 60 * 1e3
    // 7 days
  },
  3: {
    minReceipts: 150,
    minStandardPct: 0.25,
    minComplexPct: 0.1,
    minDistinctReviewers: 3,
    minDistinctTaskTypes: 5,
    maxFailureRate: 0.1,
    maxInterventionRate: 0.2,
    minTimeInCurrentTier: 14 * 24 * 60 * 60 * 1e3
    // 14 days
  },
  4: {
    minReceipts: 500,
    minStandardPct: 0.3,
    minComplexPct: 0.15,
    minDistinctReviewers: 5,
    minDistinctTaskTypes: 8,
    maxFailureRate: 0.05,
    maxInterventionRate: 0.1,
    minTimeInCurrentTier: 30 * 24 * 60 * 60 * 1e3
    // 30 days
  }
};
var MIN_SIGMA = 1;
var DEFAULT_DECAY_DAYS = 180;
var DEFAULT_DRIFT_RATE_PER_DAY = (MAX_SIGMA - MIN_SIGMA) / DEFAULT_DECAY_DAYS;

// verifier/node_modules/agent-passport-system/dist/src/core/behavioral-fingerprint.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/probe-identity.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/cross-chain.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/execution-envelope.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/execution-attestation.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/bilateral-receipt.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/feasibility.js
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/v2/hash-pointer/profile.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/governance.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/obligations.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/identity.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/receipt-ledger.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/escalation.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/data-source.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/decision-semantics.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/v2/bridge.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/evaluation-context.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/v2/bridge.js
var DEFAULT_MAX_LIFETIME_MS = 180 * 24 * 60 * 60 * 1e3;

// verifier/node_modules/agent-passport-system/dist/src/core/data-lifecycle.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/v2/human-escalation.js
init_write_policy();
var DEFAULT_FLAGGED_ACTION_CLASSES = Object.freeze([
  "org_creation",
  "third_party_attribution",
  "spend_above_threshold",
  "charter_amendment",
  "delegation_scope_expansion"
]);

// verifier/node_modules/agent-passport-system/dist/src/v2/cognitive-attestation/envelope.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/cognitive-attestation/verify.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/provisional-statement/create.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/v2/provisional-statement/promote.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/v2/provisional-statement/verify.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-weights/profile.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-primitive/canonical.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-settlement/aggregate.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-settlement/merkle.js
init_canonical();
var LEAF_TAG = Buffer.from([0]);
var NODE_TAG = Buffer.from([1]);

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-settlement/sign.js
init_canonical();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-settlement/verify.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-primitive/verify.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-primitive/construct.js
init_keys();
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/attribution-primitive/residual.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/v2/verifier-hardening/index.js
init_canonical();
var DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1e3;

// verifier/node_modules/agent-passport-system/dist/src/v2/revocation-enforcement/observation.js
init_canonical();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/accountability/construct/action.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/accountability/construct/authority-boundary.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/accountability/construct/custody.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/accountability/construct/contestability.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/accountability/construct/bundle.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/accountability/verify/action.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/accountability/verify/authority-boundary.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/accountability/verify/custody.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/accountability/verify/contestability.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/accountability/verify/bundle.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/scope-registry/registry.js
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/feasibility/compiler.js
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/scope-registry/registry.js
var DIM_SCOPE = {
  id: "scope",
  facet: "scope",
  valueType: "string_set",
  decidable: true,
  enforcement_strength: "strict",
  assurance_class: "mechanically_enforceable",
  m6Variable: "action_scope",
  comment: "requested scope must be a member of the granted scope set (M6 scope_granted)"
};
var DIM_SPEND = {
  id: "spend",
  facet: "spend",
  valueType: "numeric",
  decidable: true,
  enforcement_strength: "strict",
  assurance_class: "mechanically_enforceable",
  m6Variable: "cumulative_spend",
  comment: "cumulative spend must not exceed the delegation limit (M6 spend_within_limit)"
};
var DIM_DEPTH = {
  id: "depth",
  facet: "scope",
  valueType: "numeric",
  decidable: true,
  enforcement_strength: "strict",
  assurance_class: "mechanically_enforceable",
  m6Variable: "current_depth",
  comment: "current delegation depth must not exceed the maximum (M6 depth_within_bound)"
};
var DIM_TEMPORAL = {
  id: "temporal",
  facet: "time",
  valueType: "timestamp",
  decidable: true,
  enforcement_strength: "strict",
  assurance_class: "mechanically_enforceable",
  m6Variable: "within_window",
  comment: "action must fall within the delegation validity window and the delegation must not be revoked (M6 delegation_active, within_validity_window)"
};
var DIM_DATA_CLASS = {
  id: "data_class",
  facet: "data",
  valueType: "enum_set",
  decidable: true,
  enforcement_strength: "strict",
  assurance_class: "mechanically_enforceable",
  m6Variable: "action_data_class",
  vocabulary: ["confidential", "internal", "pii", "public", "restricted"],
  comment: "the data classes a child may touch must be a subset of the parent grant (set narrowing)"
};
var DIM_DESTINATION = {
  id: "destination",
  facet: "cross_chain",
  valueType: "string_set",
  decidable: true,
  enforcement_strength: "strict",
  assurance_class: "mechanically_enforceable",
  m6Variable: "action_destination",
  comment: "the egress destinations a child may reach must be a subset of the parent allow-list (set narrowing)"
};
var DIM_PURPOSE = {
  id: "purpose",
  facet: "scope",
  valueType: "text",
  decidable: false,
  enforcement_strength: "advisory",
  assurance_class: "evidentially_auditable",
  comment: "free-text declared purpose; self-declared agent intent, not mechanically checkable",
  does_not_assert: "The registry does not decide whether a declared free-text purpose was honored; advisory dimensions cannot be the basis of a hard deny.",
  decidablePath: "replace free-text purpose with a controlled DataPurpose code (src/types/data-source.ts) to make it a decidable enum_set dimension."
};
var CANONICAL_DIMENSIONS = [
  DIM_DATA_CLASS,
  DIM_DEPTH,
  DIM_DESTINATION,
  DIM_PURPOSE,
  DIM_SCOPE,
  DIM_SPEND,
  DIM_TEMPORAL
].slice().sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

// verifier/node_modules/agent-passport-system/dist/src/v2/context-provenance/types.js
var CHANNEL_ORDER = [
  "system-config",
  "developer",
  "user-socket",
  "retrieval-store",
  "tool-result",
  "external",
  "memory",
  "quarantine"
];

// verifier/node_modules/agent-passport-system/dist/src/v2/context-provenance/cpa.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/context-provenance/merkle.js
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/context-provenance/verify.js
init_canonical_jcs();
init_keys();
var CHANNEL_SET = new Set(CHANNEL_ORDER);
var CHANNEL_INDEX = new Map(CHANNEL_ORDER.map((c, i) => [c, i]));

// verifier/node_modules/agent-passport-system/dist/src/v2/regulated-action/verify.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/composition-check/types.js
var COMPOSITION_CHECK_RESULTS = [
  "pass",
  "fail",
  "indeterminate",
  "not_checked"
];

// verifier/node_modules/agent-passport-system/dist/src/v2/composition-check/verify.js
init_canonical_jcs();
init_keys();
var VALID_RESULTS = new Set(COMPOSITION_CHECK_RESULTS);

// verifier/node_modules/agent-passport-system/dist/src/v2/claim-evidence-types.js
var ClaimType;
(function(ClaimType2) {
  ClaimType2["IDENTITY_VERIFIED"] = "IDENTITY_VERIFIED";
  ClaimType2["AUTHORITY_TO_EXECUTE"] = "AUTHORITY_TO_EXECUTE";
  ClaimType2["ACTION_EXECUTED"] = "ACTION_EXECUTED";
  ClaimType2["BINDING_COMMITMENT"] = "BINDING_COMMITMENT";
  ClaimType2["EFFECT_SAFETY_ATTESTED"] = "EFFECT_SAFETY_ATTESTED";
  ClaimType2["DERIVATION_TRACED"] = "DERIVATION_TRACED";
  ClaimType2["CLAIM_CONTESTED"] = "CLAIM_CONTESTED";
  ClaimType2["CLAIM_RESOLVED"] = "CLAIM_RESOLVED";
  ClaimType2["BATCH_ATTESTED"] = "BATCH_ATTESTED";
  ClaimType2["EVIDENCE_CUSTODY_HELD"] = "EVIDENCE_CUSTODY_HELD";
})(ClaimType || (ClaimType = {}));
var RecordType;
(function(RecordType2) {
  RecordType2["ActionReceipt"] = "ActionReceipt";
  RecordType2["AuthorityBoundaryReceipt"] = "AuthorityBoundaryReceipt";
  RecordType2["CustodyReceipt"] = "CustodyReceipt";
  RecordType2["ContestabilityReceipt"] = "ContestabilityReceipt";
  RecordType2["APSBundle"] = "APSBundle";
  RecordType2["AccessReceipt"] = "AccessReceipt";
  RecordType2["DerivationReceipt"] = "DerivationReceipt";
  RecordType2["DecisionReceipt"] = "DecisionReceipt";
  RecordType2["ProvisionalStatement"] = "ProvisionalStatement";
  RecordType2["PromotionEvent"] = "PromotionEvent";
  RecordType2["Withdrawal"] = "Withdrawal";
  RecordType2["InstructionProvenanceReceipt"] = "InstructionProvenanceReceipt";
  RecordType2["CognitiveAttestation"] = "CognitiveAttestation";
  RecordType2["PaymentReceipt"] = "PaymentReceipt";
  RecordType2["AcpReceipt"] = "AcpReceipt";
  RecordType2["MppApsReceipt"] = "MppApsReceipt";
  RecordType2["SignedAP2Mandate"] = "SignedAP2Mandate";
  RecordType2["StripeIssuingReceipt"] = "StripeIssuingReceipt";
})(RecordType || (RecordType = {}));
var RAIL_RECEIPT_CLAIM_TYPES = {
  [RecordType.PaymentReceipt]: "rail.payment.v1",
  [RecordType.AcpReceipt]: "rail.acp.v1",
  [RecordType.MppApsReceipt]: "rail.mpp.v1",
  [RecordType.SignedAP2Mandate]: "rail.ap2.mandate.v1",
  [RecordType.StripeIssuingReceipt]: "rail.stripe_issuing.v1"
};
var EvidenceProfiles = {
  [ClaimType.AUTHORITY_TO_EXECUTE]: {
    required: [RecordType.AuthorityBoundaryReceipt],
    optional: [RecordType.DecisionReceipt],
    forbiddenSubstitutions: {
      [RecordType.ActionReceipt]: "Action receipts prove execution, not authority. The boundary ruling is a separate signer (the gateway/evaluator), and conflating them collapses the trust split that makes the audit chain meaningful."
    }
  },
  [ClaimType.BINDING_COMMITMENT]: {
    required: [RecordType.PromotionEvent, RecordType.ProvisionalStatement],
    optional: [RecordType.DecisionReceipt],
    forbiddenSubstitutions: {
      [RecordType.ActionReceipt]: "Action receipts prove execution or communication, not binding commitment."
    }
  },
  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.IDENTITY_VERIFIED]: {
    required: [],
    forbiddenSubstitutions: {}
  },
  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.ACTION_EXECUTED]: {
    required: [],
    forbiddenSubstitutions: {}
  },
  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.EFFECT_SAFETY_ATTESTED]: {
    required: [],
    forbiddenSubstitutions: {}
  },
  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.DERIVATION_TRACED]: {
    required: [],
    forbiddenSubstitutions: {}
  },
  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.CLAIM_CONTESTED]: {
    required: [],
    forbiddenSubstitutions: {}
  },
  // TODO: populate required/optional records and forbiddenSubstitutions.
  [ClaimType.CLAIM_RESOLVED]: {
    required: [],
    forbiddenSubstitutions: {}
  },
  [ClaimType.BATCH_ATTESTED]: {
    required: [RecordType.APSBundle],
    forbiddenSubstitutions: {}
  },
  [ClaimType.EVIDENCE_CUSTODY_HELD]: {
    required: [RecordType.CustodyReceipt],
    forbiddenSubstitutions: {
      [RecordType.ActionReceipt]: "Action receipts prove what was done, not who held the evidence afterward."
    }
  }
};

// verifier/node_modules/agent-passport-system/dist/src/v2/offline-verifier/context.js
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/v2/offline-verifier/conformance-runner.js
init_canonical_jcs();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/interop/agent-json-bridge.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/data-source-attribution.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/decision-equivalence.js
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/adapters/crewai.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/adapters/langchain.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/adapters/mcp.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/adapters/gonka.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/adapters/ibac.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/storage/volatile-backend.js
init_canonical();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/storage/receipt-bundle.js
init_canonical();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/core/tool-integrity.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/behavioral-memory.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/core/behavioral-memory-receipt.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/v2/mutual-auth/index.js
init_certificate();

// verifier/node_modules/agent-passport-system/dist/src/v2/mutual-auth/trust-bundle.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/mutual-auth/index.js
init_handshake();

// verifier/node_modules/agent-passport-system/dist/src/v2/trust-policy/policy.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/instruction-provenance/canonicalize.js
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/instruction-provenance/envelope.js
var PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

// verifier/node_modules/agent-passport-system/dist/src/v2/instruction-provenance/verify.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/scope-resolution.js
function resolveSpendLimitCents(delegation, opts = {}) {
  const limits = delegation.scope?.resource_limits ?? {};
  const constraints = delegation.scope?.constraints ?? {};
  const canonicalKey = opts.canonicalKey ?? "spend_limit_cents";
  const v1 = limits[canonicalKey];
  if (_isUsableNumber(v1))
    return v1;
  if (canonicalKey !== "commerce.spend_limit") {
    const v2 = limits["commerce.spend_limit"];
    if (_isUsableNumber(v2))
      return v2;
  }
  const v3 = constraints.spend_limit_cents;
  if (typeof v3 === "string" && v3.length > 0) {
    const parsed = Number(v3);
    if (_isUsableNumber(parsed))
      return parsed;
  }
  return null;
}
function _isUsableNumber(v) {
  return typeof v === "number" && Number.isFinite(v) && v >= 0;
}

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/canonicalize.js
init_canonical_jcs();
import { createHash } from "node:crypto";
function sha256Hex2(s) {
  return createHash("sha256").update(s, "utf8").digest("hex");
}
function canonicalizeReceiptForId(receipt) {
  return canonicalizeJCS({ ...receipt, receipt_id: "", signature: "" });
}
function canonicalizeReceiptForSig(receipt) {
  return canonicalizeJCS({ ...receipt, signature: "" });
}
function canonicalizeDenialForId(denial) {
  return canonicalizeJCS({ ...denial, receipt_id: "", signature: "" });
}
function canonicalizeDenialForSig(denial) {
  return canonicalizeJCS({ ...denial, signature: "" });
}

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/hooks.js
init_keys();
init_canonical();

// verifier/node_modules/agent-passport-system/dist/src/core/did-uri.js
init_did();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/hooks.js
var RAIL_PAYMENT_RECEIPT_CLAIM_TYPE = "rail.payment.v1";
var LEGACY_PAYMENT_RECEIPT_CLAIM_TYPE = "aps:payment_receipt:v1";
var RAIL_PAYMENT_DENIAL_CLAIM_TYPE = "rail.payment.denial.v1";
var LEGACY_PAYMENT_DENIAL_CLAIM_TYPE = "aps:payment_denial:v1";
var RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE = "rail.budget_reservation.permit.v1";
var RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE = "rail.budget_reservation.release.v1";
var RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE = "rail.budget_reservation.denial.v1";
var VALID_DENIAL_REASONS = [
  "no_commerce_scope",
  "spend_limit_exceeded",
  "wallet_revoked",
  "time_window_violation",
  "rail_error",
  "requires_owner_confirmation"
];
function verifyPaymentReceipt(receipt) {
  if (receipt.claim_type !== LEGACY_PAYMENT_RECEIPT_CLAIM_TYPE && receipt.claim_type !== RAIL_PAYMENT_RECEIPT_CLAIM_TYPE && receipt.claim_type !== RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE && receipt.claim_type !== RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE) {
    return { valid: false, reason: "INVALID_CLAIM_TYPE" };
  }
  if (receipt.claim_type === RAIL_PAYMENT_RECEIPT_CLAIM_TYPE) {
    if (receipt.timestamp !== receipt.issued_at) {
      return { valid: false, reason: "INVALID_CLAIM_TYPE" };
    }
    if (!receipt.scope_of_claim || typeof receipt.scope_of_claim.asserts !== "string" || receipt.scope_of_claim.asserts.length === 0) {
      return { valid: false, reason: "INVALID_CLAIM_TYPE" };
    }
  }
  const expectedId = sha256Hex2(canonicalizeReceiptForId(receipt));
  if (receipt.receipt_id !== expectedId) {
    return { valid: false, reason: "RECEIPT_ID_MISMATCH" };
  }
  if (typeof receipt.signer_did === "string" && receipt.signer_did.startsWith("did:")) {
    return { valid: false, reason: "DID_RESOLVER_MISSING" };
  }
  if (!verify(canonicalizeReceiptForSig(receipt), receipt.signature, receipt.signer_did)) {
    return { valid: false, reason: "SIGNATURE_INVALID" };
  }
  return { valid: true };
}
function verifyPaymentDenial(denial) {
  if (denial.claim_type !== LEGACY_PAYMENT_DENIAL_CLAIM_TYPE && denial.claim_type !== RAIL_PAYMENT_DENIAL_CLAIM_TYPE && denial.claim_type !== RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE) {
    return { valid: false, reason: "INVALID_CLAIM_TYPE" };
  }
  if (denial.claim_type === RAIL_PAYMENT_DENIAL_CLAIM_TYPE) {
    if (denial.timestamp !== denial.issued_at) {
      return { valid: false, reason: "INVALID_CLAIM_TYPE" };
    }
    if (!denial.scope_of_claim || typeof denial.scope_of_claim.asserts !== "string" || denial.scope_of_claim.asserts.length === 0) {
      return { valid: false, reason: "INVALID_CLAIM_TYPE" };
    }
  }
  if (!VALID_DENIAL_REASONS.includes(denial.denial_reason)) {
    return { valid: false, reason: "INVALID_DENIAL_REASON" };
  }
  const expectedId = sha256Hex2(canonicalizeDenialForId(denial));
  if (denial.receipt_id !== expectedId) {
    return { valid: false, reason: "RECEIPT_ID_MISMATCH" };
  }
  if (typeof denial.signer_did === "string" && denial.signer_did.startsWith("did:")) {
    return { valid: false, reason: "DID_RESOLVER_MISSING" };
  }
  if (!verify(canonicalizeDenialForSig(denial), denial.signature, denial.signer_did)) {
    return { valid: false, reason: "SIGNATURE_INVALID" };
  }
  return { valid: true };
}

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/nano.js
var RAW_PER_XNO = BigInt("1000000000000000000000000000000");

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/ap2/index.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/conformance/harness.js
var HARNESS_ISSUER_PRIV = "aa".repeat(32);
var DELEGATION_REF = "d".repeat(64);
var ACTION_REF = "a".repeat(64);
var TX_PROOF = "b".repeat(64);
function _baseDelegation(walletId, currency) {
  return {
    receipt_id: DELEGATION_REF,
    scope: ["commerce.purchase"],
    spend_limit_base_units: "1000000000000000000000000000000",
    // 1 unit
    wallet_id: walletId,
    currency
  };
}
function _input(ctx, delegation, amount, required_scope = "commerce.purchase") {
  return {
    delegation,
    required_scope,
    amount_base_units: amount,
    currency: ctx.rail.currency,
    now: ctx.now
  };
}
var SCN_001 = {
  id: "SCN-001",
  description: "preAuthorize accepts when delegation has commerce scope and amount within budget",
  async run(ctx) {
    const delegation = _baseDelegation(ctx.walletId, ctx.rail.currency);
    const result2 = ctx.hooks.preAuthorize(_input(ctx, delegation, "1000"), ctx.rail);
    if (!result2.ok) {
      return { ok: false, reason: `expected ok=true, got denial=${result2.denial_reason}` };
    }
    return { ok: true };
  }
};
var SCN_002 = {
  id: "SCN-002",
  description: "preAuthorize rejects with 'no_commerce_scope' when required_scope absent from delegation",
  async run(ctx) {
    const delegation = {
      ..._baseDelegation(ctx.walletId, ctx.rail.currency),
      scope: ["commerce.refund"]
      // no purchase
    };
    const result2 = ctx.hooks.preAuthorize(_input(ctx, delegation, "1000"), ctx.rail);
    if (result2.ok)
      return { ok: false, reason: "expected denial, got ok" };
    if (result2.denial_reason !== "no_commerce_scope") {
      return {
        ok: false,
        reason: `expected denial_reason=no_commerce_scope, got ${result2.denial_reason}`
      };
    }
    return { ok: true };
  }
};
var SCN_003 = {
  id: "SCN-003",
  description: "preAuthorize rejects with 'spend_limit_exceeded' when amount exceeds budget",
  async run(ctx) {
    const delegation = {
      ..._baseDelegation(ctx.walletId, ctx.rail.currency),
      spend_limit_base_units: "1000"
    };
    const result2 = ctx.hooks.preAuthorize(_input(ctx, delegation, "10000"), ctx.rail);
    if (result2.ok)
      return { ok: false, reason: "expected denial, got ok" };
    if (result2.denial_reason !== "spend_limit_exceeded") {
      return {
        ok: false,
        reason: `expected denial_reason=spend_limit_exceeded, got ${result2.denial_reason}`
      };
    }
    return { ok: true };
  }
};
var SCN_004 = {
  id: "SCN-004",
  description: "preAuthorize rejects with 'wallet_revoked' when the bound wallet has been revoked",
  async run(ctx) {
    await ctx.rail.revokeWallet(ctx.walletId);
    if (!ctx.rail.isWalletRevoked(ctx.walletId)) {
      return { ok: false, reason: "isWalletRevoked returned false after revokeWallet" };
    }
    const delegation = _baseDelegation(ctx.walletId, ctx.rail.currency);
    const result2 = ctx.hooks.preAuthorize(_input(ctx, delegation, "1000"), ctx.rail);
    if (result2.ok)
      return { ok: false, reason: "expected denial, got ok" };
    if (result2.denial_reason !== "wallet_revoked") {
      return {
        ok: false,
        reason: `expected denial_reason=wallet_revoked, got ${result2.denial_reason}`
      };
    }
    return { ok: true };
  }
};
var SCN_005 = {
  id: "SCN-005",
  description: "preAuthorize rejects with 'time_window_violation' after delegation.not_after has expired",
  async run(ctx) {
    const expired = new Date(ctx.now.getTime() - 6e4).toISOString();
    const delegation = {
      ..._baseDelegation(ctx.walletId, ctx.rail.currency),
      not_after: expired
    };
    const result2 = ctx.hooks.preAuthorize(_input(ctx, delegation, "1000"), ctx.rail);
    if (result2.ok)
      return { ok: false, reason: "expected denial, got ok" };
    if (result2.denial_reason !== "time_window_violation") {
      return {
        ok: false,
        reason: `expected denial_reason=time_window_violation, got ${result2.denial_reason}`
      };
    }
    return { ok: true };
  }
};
var SCN_006 = {
  id: "SCN-006",
  description: "emitReceipt produces a PaymentReceipt with a valid Ed25519 signature",
  async run(ctx) {
    const receipt = ctx.hooks.emitReceipt({
      delegation_ref: DELEGATION_REF,
      action_ref: ACTION_REF,
      rail_name: ctx.rail.name,
      amount_base_units: "1000",
      currency: ctx.rail.currency,
      tx_proof: TX_PROOF,
      invoice_id: `inv-${ctx.walletId}`,
      issued_at: ctx.now.toISOString()
    }, ctx.issuerPrivateKeyHex);
    if (receipt.claim_type !== "aps:payment_receipt:v1") {
      return { ok: false, reason: `claim_type=${receipt.claim_type}` };
    }
    if (receipt.signature.length !== 128) {
      return { ok: false, reason: `signature length=${receipt.signature.length}, expected 128` };
    }
    if (receipt.receipt_id.length !== 64) {
      return { ok: false, reason: `receipt_id length=${receipt.receipt_id.length}, expected 64` };
    }
    const v = verifyPaymentReceipt(receipt);
    if (!v.valid)
      return { ok: false, reason: `verifyPaymentReceipt failed: ${v.reason}` };
    return { ok: true };
  }
};
var SCN_007 = {
  id: "SCN-007",
  description: "emitReceipt output round-trips through JSON canonicalization and verifies clean",
  async run(ctx) {
    const receipt = ctx.hooks.emitReceipt({
      delegation_ref: DELEGATION_REF,
      action_ref: ACTION_REF,
      rail_name: ctx.rail.name,
      amount_base_units: "1000",
      currency: ctx.rail.currency,
      tx_proof: TX_PROOF,
      issued_at: ctx.now.toISOString()
    }, ctx.issuerPrivateKeyHex);
    const roundTripped = JSON.parse(JSON.stringify(receipt));
    const v = verifyPaymentReceipt(roundTripped);
    if (!v.valid) {
      return { ok: false, reason: `round-trip verify failed: ${v.reason}` };
    }
    return { ok: true };
  }
};
var SCN_008 = {
  id: "SCN-008",
  description: "emitDenial produces a PaymentDenial with a valid Ed25519 signature",
  async run(ctx) {
    const denial = ctx.hooks.emitDenial({
      delegation_ref: DELEGATION_REF,
      action_ref: ACTION_REF,
      rail_name: ctx.rail.name,
      amount_base_units: "1000",
      currency: ctx.rail.currency,
      denial_reason: "no_commerce_scope",
      reason_detail: "scope 'commerce.purchase' not in delegation",
      issued_at: ctx.now.toISOString()
    }, ctx.issuerPrivateKeyHex);
    if (denial.claim_type !== "aps:payment_denial:v1") {
      return { ok: false, reason: `claim_type=${denial.claim_type}` };
    }
    if (denial.signature.length !== 128) {
      return { ok: false, reason: `signature length=${denial.signature.length}, expected 128` };
    }
    const v = verifyPaymentDenial(denial);
    if (!v.valid)
      return { ok: false, reason: `verifyPaymentDenial failed: ${v.reason}` };
    return { ok: true };
  }
};
var SCN_009 = {
  id: "SCN-009",
  description: "revokeWallet() halts subsequent preAuthorize calls bound to that wallet",
  async run(ctx) {
    const before = ctx.hooks.preAuthorize(_input(ctx, _baseDelegation(ctx.walletId, ctx.rail.currency), "1000"), ctx.rail);
    if (!before.ok) {
      return {
        ok: false,
        reason: `pre-revocation preAuthorize unexpectedly denied: ${before.denial_reason}`
      };
    }
    const revoked = await ctx.rail.revokeWallet(ctx.walletId);
    if (revoked !== true) {
      return { ok: false, reason: "revokeWallet did not return true" };
    }
    const second = await ctx.rail.revokeWallet(ctx.walletId);
    if (second !== true) {
      return { ok: false, reason: "revokeWallet not idempotent (second call returned non-true)" };
    }
    const after = ctx.hooks.preAuthorize(_input(ctx, _baseDelegation(ctx.walletId, ctx.rail.currency), "1000"), ctx.rail);
    if (after.ok) {
      return { ok: false, reason: "preAuthorize accepted after revokeWallet" };
    }
    if (after.denial_reason !== "wallet_revoked") {
      return {
        ok: false,
        reason: `expected denial_reason=wallet_revoked, got ${after.denial_reason}`
      };
    }
    return { ok: true };
  }
};
var SCN_010 = {
  id: "SCN-010",
  description: "emitted receipt.delegation_ref equals the input delegation receipt_id",
  async run(ctx) {
    const inputRef = "c".repeat(64);
    const receipt = ctx.hooks.emitReceipt({
      delegation_ref: inputRef,
      action_ref: ACTION_REF,
      rail_name: ctx.rail.name,
      amount_base_units: "1000",
      currency: ctx.rail.currency,
      tx_proof: TX_PROOF,
      issued_at: ctx.now.toISOString()
    }, ctx.issuerPrivateKeyHex);
    if (receipt.delegation_ref !== inputRef) {
      return {
        ok: false,
        reason: `delegation_ref mismatch: got ${receipt.delegation_ref}, expected ${inputRef}`
      };
    }
    return { ok: true };
  }
};
var STANDARD_SCENARIOS = Object.freeze([
  SCN_001,
  SCN_002,
  SCN_003,
  SCN_004,
  SCN_005,
  SCN_006,
  SCN_007,
  SCN_008,
  SCN_009,
  SCN_010
]);

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/conformance/binding-harness.js
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/acp/index.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/csv.js
function csvToList(s) {
  if (!s)
    return [];
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/acp/index.js
function mapAcpDenialToFoundation(reason) {
  switch (reason) {
    case "spend_limit_exceeded":
      return "spend_limit_exceeded";
    case "wallet_revoked":
      return "wallet_revoked";
    case "no_commerce_scope":
      return "no_commerce_scope";
    case "delegation_expired":
      return "time_window_violation";
    case "merchant_not_allowed":
    case "currency_mismatch":
    case "idempotency_conflict":
    case "invalid_session_state":
    case "api_version_mismatch":
      return "rail_error";
    case "requires_owner_confirmation":
      return "requires_owner_confirmation";
  }
}
function delegationToAcpAllowed(delegation) {
  const constraints = delegation.scope?.constraints ?? {};
  return {
    allowed_merchants: csvToList(constraints.allowed_merchants),
    allowed_currencies: csvToList(constraints.allowed_currencies).map((s) => s.toLowerCase()),
    max_total: resolveSpendLimitCents(delegation),
    valid_until: delegation.policy_context?.valid_until
  };
}

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/mpp/index.js
init_canonical_jcs();
init_keys();
function mapMppDenialToFoundation(reason) {
  switch (reason) {
    case "spend_limit_exceeded":
      return "spend_limit_exceeded";
    case "wallet_revoked":
      return "wallet_revoked";
    case "no_payment_scope":
      return "no_commerce_scope";
    case "delegation_expired":
    case "challenge_expired":
      return "time_window_violation";
    case "method_not_allowed":
    case "currency_not_allowed":
    case "invalid_authorization":
    case "session_replay":
    case "mpp_version_mismatch":
      return "rail_error";
    case "requires_owner_confirmation":
      return "requires_owner_confirmation";
  }
}
function delegationToMppAllowed(delegation) {
  const constraints = delegation.scope?.constraints ?? {};
  return {
    allowed_methods: csvToList(constraints.allowed_payment_methods),
    allowed_currencies: csvToList(constraints.allowed_currencies).map((s) => s.toLowerCase()),
    max_amount_per_charge: resolveSpendLimitCents(delegation),
    valid_until: delegation.policy_context?.valid_until
  };
}

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/stripe-issuing/primitives.js
function defaultMapDelegationToSpendingControls(delegation) {
  const constraints = delegation.scope.constraints ?? {};
  const limit = resolveSpendLimitCents(delegation);
  if (limit === null || limit <= 0) {
    throw new Error("StripeIssuingRail: delegation must define a positive spend cap (resource_limits.spend_limit_cents, commerce.spend_limit, or constraints.spend_limit_cents)");
  }
  const sc = {
    spending_limits: [{ amount: Math.floor(limit), interval: "all_time" }]
  };
  const allowedCats = csvToList(constraints.allowed_merchant_categories);
  if (allowedCats.length > 0)
    sc.allowed_categories = allowedCats;
  const allowedCountries = csvToList(constraints.allowed_merchant_countries);
  if (allowedCountries.length > 0)
    sc.allowed_merchant_countries = allowedCountries;
  return sc;
}

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/conformance/binding-harness.js
var ap2Adapter = {
  name: "ap2",
  resolveSpendCap(delegation) {
    return resolveSpendLimitCents(delegation, { canonicalKey: "commerce.spend_limit" });
  },
  mapDenialToFoundation(reason) {
    return _isFoundationReason(reason) ? reason : null;
  }
};
var x402Adapter = {
  name: "x402",
  resolveSpendCap(delegation) {
    return resolveSpendLimitCents(delegation);
  },
  mapDenialToFoundation(_reason) {
    return "rail_error";
  }
};
var stripeIssuingAdapter = {
  name: "stripe-issuing",
  resolveSpendCap(delegation) {
    try {
      const sc = defaultMapDelegationToSpendingControls(delegation);
      const limit = sc.spending_limits?.[0];
      if (limit === void 0)
        return null;
      return limit.amount;
    } catch {
      return resolveSpendLimitCents(delegation);
    }
  },
  mapDenialToFoundation(reason) {
    return _isFoundationReason(reason) ? reason : null;
  }
};
var acpAdapter = {
  name: "acp",
  resolveSpendCap(delegation) {
    return delegationToAcpAllowed(delegation).max_total;
  },
  mapDenialToFoundation(reason) {
    if (_isFoundationReason(reason))
      return reason;
    if (_isAcpReason(reason))
      return mapAcpDenialToFoundation(reason);
    return null;
  }
};
var mppAdapter = {
  name: "mpp",
  resolveSpendCap(delegation) {
    return delegationToMppAllowed(delegation).max_amount_per_charge;
  },
  mapDenialToFoundation(reason) {
    if (_isFoundationReason(reason))
      return reason;
    if (_isMppReason(reason))
      return mapMppDenialToFoundation(reason);
    return null;
  }
};
var BUILTIN_BINDING_ADAPTERS = Object.freeze([
  ap2Adapter,
  x402Adapter,
  stripeIssuingAdapter,
  acpAdapter,
  mppAdapter
]);
var FOUNDATION_REASONS = /* @__PURE__ */ new Set([
  "no_commerce_scope",
  "spend_limit_exceeded",
  "wallet_revoked",
  "time_window_violation",
  "rail_error",
  "requires_owner_confirmation"
]);
function _isFoundationReason(s) {
  return FOUNDATION_REASONS.has(s);
}
var ACP_REASONS = /* @__PURE__ */ new Set([
  "spend_limit_exceeded",
  "merchant_not_allowed",
  "delegation_expired",
  "currency_mismatch",
  "wallet_revoked",
  "no_commerce_scope",
  "idempotency_conflict",
  "invalid_session_state",
  "api_version_mismatch",
  "requires_owner_confirmation"
]);
function _isAcpReason(s) {
  return ACP_REASONS.has(s);
}
var MPP_REASONS = /* @__PURE__ */ new Set([
  "spend_limit_exceeded",
  "method_not_allowed",
  "currency_not_allowed",
  "delegation_expired",
  "no_payment_scope",
  "challenge_expired",
  "invalid_authorization",
  "session_replay",
  "wallet_revoked",
  "mpp_version_mismatch",
  "requires_owner_confirmation"
]);
function _isMppReason(s) {
  return MPP_REASONS.has(s);
}

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/cycles/index.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/cycles/evidence-resolution.js
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/payment-rails/cycles/index.js
var CORRESPONDENCE_NOT_COMPARED = Object.freeze([
  "amount",
  "unit",
  "action",
  "server_id"
]);

// verifier/node_modules/agent-passport-system/dist/src/v2/policy-bundle/bundle.js
init_keys();
init_did();
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/adapters/remote-signer/local-signer.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/adapters/remote-signer/verify.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/core/evidence-bundle.js
init_keys();
init_canonical();
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/profiles/mcp/authorization-v1.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/profiles/a2a/identity-v1.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/receipt-core/receipt.js
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/authority-delegation/canonical.js
init_canonical_jcs();
init_keys();
import { createHash as createHash2 } from "node:crypto";
var AUTHORITY_DELEGATION_ID_DOMAIN = "APS-AUTHORITY-DELEGATION-ID-V1\0";
var AUTHORITY_DELEGATION_SIGNATURE_DOMAIN = "APS-AUTHORITY-DELEGATION-SIGNATURE-V1\0";
function sha256Hex3(value) {
  return createHash2("sha256").update(value, "utf8").digest("hex");
}
function authorityDelegationIdInput(body) {
  return AUTHORITY_DELEGATION_ID_DOMAIN + canonicalizeJCS(body);
}
function computeAuthorityDelegationId(body) {
  return `sha256:${sha256Hex3(authorityDelegationIdInput(body))}`;
}
function authorityDelegationSignatureInput(delegation) {
  return AUTHORITY_DELEGATION_SIGNATURE_DOMAIN + canonicalizeJCS(delegation);
}
function verifyAuthorityDelegationSignature(delegation, publicKey) {
  const { signature, ...unsigned } = delegation;
  return verify(authorityDelegationSignatureInput(unsigned), signature, publicKey);
}
function authorityDelegationBody(delegation) {
  const { delegation_id: _delegationId, signature: _signature, ...body } = delegation;
  return body;
}

// verifier/node_modules/agent-passport-system/dist/src/v2/authority-delegation/plain-data.js
import { types } from "node:util";
var functionToString = Function.prototype.toString;
var isRawJSON = typeof JSON.isRawJSON === "function" ? JSON.isRawJSON : () => false;
var NOT_PLAIN_DATA = Symbol("aps:not-plain-json-data");
function isProxy(value) {
  return (typeof value === "object" || typeof value === "function") && value !== null && types.isProxy(value);
}
function isPlainScalar(value) {
  if (value === null)
    return true;
  switch (typeof value) {
    case "boolean":
    case "string":
      return true;
    case "number":
      return Number.isFinite(value);
    default:
      return false;
  }
}
function isIntrinsicPrototype(candidate, name) {
  try {
    if (isProxy(candidate))
      return false;
    const constructorDescriptor = Object.getOwnPropertyDescriptor(candidate, "constructor");
    if (!constructorDescriptor || !("value" in constructorDescriptor))
      return false;
    const constructor = constructorDescriptor.value;
    if (typeof constructor !== "function" || isProxy(constructor))
      return false;
    const prototypeDescriptor = Object.getOwnPropertyDescriptor(constructor, "prototype");
    if (!prototypeDescriptor || !("value" in prototypeDescriptor) || prototypeDescriptor.value !== candidate || prototypeDescriptor.writable !== false || prototypeDescriptor.configurable !== false) {
      return false;
    }
    return functionToString.call(constructor) === `function ${name}() { [native code] }`;
  } catch {
    return false;
  }
}
function newPrototypeIntrinsicCache() {
  return { objectPrototypes: /* @__PURE__ */ new Map(), arrayPrototypes: /* @__PURE__ */ new Map() };
}
function isArrayPrototypeOfSomeRealm(candidate, cache) {
  if (candidate === null || typeof candidate !== "object")
    return false;
  const cached = cache.arrayPrototypes.get(candidate);
  if (cached !== void 0)
    return cached;
  const verdict = isIntrinsicPrototype(candidate, "Array");
  cache.arrayPrototypes.set(candidate, verdict);
  return verdict;
}
function isPlainObjectPrototype(prototype, cache) {
  if (prototype === null)
    return true;
  if (typeof prototype !== "object")
    return false;
  const cached = cache.objectPrototypes.get(prototype);
  if (cached !== void 0)
    return cached;
  const verdict = isIntrinsicPrototype(prototype, "Object");
  cache.objectPrototypes.set(prototype, verdict);
  return verdict;
}
function plainArrayLength(value, cache) {
  if (!isArrayPrototypeOfSomeRealm(Object.getPrototypeOf(value), cache))
    return null;
  if (Object.getOwnPropertySymbols(value).length > 0)
    return null;
  const toJSONDescriptor = Object.getOwnPropertyDescriptor(value, "toJSON");
  if (toJSONDescriptor && (!("value" in toJSONDescriptor) || typeof toJSONDescriptor.value === "function"))
    return null;
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  const length = lengthDescriptor ? lengthDescriptor.value : void 0;
  if (typeof length !== "number" || !Number.isInteger(length) || length < 0)
    return null;
  return length;
}
function plainObjectKeys(value, cache) {
  if (types.isBoxedPrimitive(value) || isRawJSON(value))
    return null;
  if (!isPlainObjectPrototype(Object.getPrototypeOf(value), cache))
    return null;
  if (Object.getOwnPropertySymbols(value).length > 0)
    return null;
  return Object.getOwnPropertyNames(value);
}
function snapshotPlainData(root) {
  let output;
  const onPath = /* @__PURE__ */ new Set();
  const done = /* @__PURE__ */ new Map();
  const prototypeCache = newPrototypeIntrinsicCache();
  const frames = [];
  const place = (result2) => {
    if (frames.length === 0) {
      output = result2;
      return;
    }
    const frame = frames[frames.length - 1];
    if (frame.kind === "array") {
      frame.copy[frame.index] = result2;
      return;
    }
    Object.defineProperty(frame.copy, frame.keys[frame.index], {
      value: result2,
      writable: true,
      enumerable: true,
      configurable: true
    });
  };
  const rejectOpenContainer = () => {
    const frame = frames.pop();
    onPath.delete(frame.source);
    done.set(frame.source, NOT_PLAIN_DATA);
    place(NOT_PLAIN_DATA);
  };
  let member = root;
  let hasMember = true;
  while (hasMember) {
    try {
      if (isPlainScalar(member)) {
        place(member);
      } else if (isProxy(member)) {
        place(NOT_PLAIN_DATA);
      } else if (typeof member !== "object" || member === null) {
        place(NOT_PLAIN_DATA);
      } else if (onPath.has(member)) {
        place(NOT_PLAIN_DATA);
      } else if (done.has(member)) {
        place(done.get(member));
      } else if (Array.isArray(member)) {
        const length = plainArrayLength(member, prototypeCache);
        if (length === null) {
          done.set(member, NOT_PLAIN_DATA);
          place(NOT_PLAIN_DATA);
        } else {
          const copy = [];
          done.set(member, copy);
          place(copy);
          onPath.add(member);
          frames.push({ kind: "array", source: member, copy, length, index: -1 });
        }
      } else {
        const keys = plainObjectKeys(member, prototypeCache);
        if (keys === null) {
          done.set(member, NOT_PLAIN_DATA);
          place(NOT_PLAIN_DATA);
        } else {
          const copy = {};
          done.set(member, copy);
          place(copy);
          onPath.add(member);
          frames.push({ kind: "object", source: member, copy, keys, index: -1 });
        }
      }
    } catch {
      place(NOT_PLAIN_DATA);
    }
    hasMember = false;
    while (frames.length > 0) {
      const frame = frames[frames.length - 1];
      const next = frame.index + 1;
      if (next >= (frame.kind === "array" ? frame.length : frame.keys.length)) {
        onPath.delete(frame.source);
        frames.pop();
        continue;
      }
      frame.index = next;
      let descriptor;
      try {
        descriptor = Object.getOwnPropertyDescriptor(frame.source, frame.kind === "array" ? String(next) : frame.keys[next]);
      } catch {
        descriptor = void 0;
      }
      if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
        rejectOpenContainer();
        continue;
      }
      member = descriptor.value;
      hasMember = true;
      break;
    }
  }
  return output;
}
function readPlainDataChainContainer(value, minLength, maxLength, rejection) {
  if (rejection)
    rejection.reason = "not-a-container";
  try {
    if (isProxy(value) || typeof value !== "object" || value === null)
      return null;
    if (!Array.isArray(value))
      return null;
    const length = plainArrayLength(value, newPrototypeIntrinsicCache());
    if (length !== null && length > maxLength) {
      if (rejection)
        rejection.reason = "over-ceiling";
      return null;
    }
    if (length === null || length < minLength)
      return null;
    const members = new Array(length);
    for (let i = 0; i < length; i++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
      if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true)
        return null;
      members[i] = descriptor.value;
    }
    return members;
  } catch {
    return null;
  }
}

// verifier/node_modules/agent-passport-system/dist/src/v2/authority-delegation/scope.js
var ASCII_ONLY = /^[\x00-\x7f]*$/;
function isValidScopeGrant(grant) {
  if (typeof grant !== "string" || grant.length === 0)
    return false;
  if (!ASCII_ONLY.test(grant))
    return false;
  if (grant === "*")
    return true;
  const parts = grant.split(":");
  if (parts.at(-1) === "*")
    parts.pop();
  return parts.length > 0 && parts.every((part) => part.length > 0 && !part.includes("*"));
}
function scopeGrantCovers(parent, child) {
  if (parent === "*")
    return true;
  if (parent.endsWith(":*")) {
    const prefix = parent.slice(0, -2);
    const childPrefix = child.endsWith(":*") ? child.slice(0, -2) : child;
    return childPrefix === prefix || childPrefix.startsWith(prefix + ":");
  }
  return parent === child;
}
function grantsAreCanonical(grants) {
  if (!Array.isArray(grants))
    return false;
  for (let i = 0; i < grants.length; i++) {
    const grant = grants[i];
    if (!isValidScopeGrant(grant))
      return false;
    if (i > 0 && grants[i - 1] >= grant)
      return false;
  }
  const grantSet = new Set(grants);
  for (const grant of grants) {
    if (grant === "*")
      continue;
    if (grantSet.has("*"))
      return false;
    const prefix = grant.endsWith(":*") ? grant.slice(0, -2) : grant;
    const segments = prefix.split(":");
    for (let m = 1; m <= segments.length; m++) {
      const candidate = segments.slice(0, m).join(":") + ":*";
      if (candidate !== grant && grantSet.has(candidate))
        return false;
    }
  }
  return true;
}
function scopeNarrows(parent, child) {
  const parentSet = new Set(parent);
  if (parentSet.has("*"))
    return true;
  for (const grant of child) {
    if (typeof grant !== "string")
      return false;
    if (parentSet.has(grant))
      continue;
    const prefix = grant.endsWith(":*") ? grant.slice(0, -2) : grant;
    const segments = prefix.split(":");
    let covered = false;
    for (let m = 1; m <= segments.length; m++) {
      const candidate = segments.slice(0, m).join(":") + ":*";
      if (parentSet.has(candidate)) {
        covered = true;
        break;
      }
    }
    if (!covered)
      return false;
  }
  return true;
}

// verifier/node_modules/agent-passport-system/dist/src/v2/authority-delegation/types.js
var AUTHORITY_DELEGATION_RECORD_TYPE = "aps:authority-delegation:v1";
var AUTHORITY_DELEGATION_VERSION = "1.0";
var SCOPE_PROFILE_V1 = "aps-hierarchical-v1";
var REPUTATION_PROFILE_V1 = "aps-score-0-100-v1";
var VALUES_PROFILE_V1 = "aps-values-identifiers-v1";
var REVERSIBILITY_PROFILE_V1 = "aps-tci-v1";

// verifier/node_modules/agent-passport-system/dist/src/v2/authority-delegation/schema.js
var ID = /^sha256:[0-9a-f]{64}$/;
var HEX_32 = /^[0-9a-f]{32}$/;
var HEX_128 = /^[0-9a-f]{128}$/;
var DECIMAL = /^(0|[1-9][0-9]*)$/;
var isAdmissibleIdentifier = (value) => typeof value === "string" && value.length > 0;
var MAX_QUANTITY = 9223372036854775807n;
var CANONICAL_TIMESTAMP = /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)\.[0-9]{3}Z$/;
var DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
function isLeapYear(year) {
  return year % 4 === 0 && year % 100 !== 0 || year % 400 === 0;
}
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : null;
}
function exactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, i) => key === wanted[i]);
}
function isIJSONString(value) {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    let codePoint = unit;
    if (unit >= 55296 && unit <= 56319) {
      const next = value.charCodeAt(++i);
      if (!(next >= 56320 && next <= 57343))
        return false;
      codePoint = (unit - 55296) * 1024 + (next - 56320) + 65536;
    } else if (unit >= 56320 && unit <= 57343) {
      return false;
    }
    if (codePoint >= 64976 && codePoint <= 65007)
      return false;
    if ((codePoint & 65535) >= 65534)
      return false;
  }
  return true;
}
function isIJSONValue(value) {
  if (value === null)
    return true;
  switch (typeof value) {
    case "object":
      return true;
    case "string":
      return isIJSONString(value);
    case "number":
      return Number.isFinite(value);
    case "boolean":
      return true;
    default:
      return false;
  }
}
function recordStringsAreIJSON(root) {
  const visited = /* @__PURE__ */ new Set();
  const checked = /* @__PURE__ */ new Set();
  const wellFormed = (value) => {
    if (checked.has(value))
      return true;
    if (!isIJSONString(value))
      return false;
    checked.add(value);
    return true;
  };
  const memberIsIJSON = (value) => typeof value === "string" ? wellFormed(value) : isIJSONValue(value);
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === null || typeof current !== "object")
      continue;
    if (visited.has(current))
      continue;
    visited.add(current);
    if (Array.isArray(current)) {
      for (const item of current) {
        if (!memberIsIJSON(item))
          return false;
        if (item !== null && typeof item === "object")
          stack.push(item);
      }
    } else {
      for (const key of Object.keys(current)) {
        if (!wellFormed(key))
          return false;
        const member = current[key];
        if (!memberIsIJSON(member))
          return false;
        if (member !== null && typeof member === "object")
          stack.push(member);
      }
    }
  }
  return true;
}
function isCanonicalTimestamp(value) {
  if (typeof value !== "string")
    return false;
  const match = CANONICAL_TIMESTAMP.exec(value);
  if (!match)
    return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const maxDay = month === 2 && isLeapYear(year) ? 29 : DAYS_IN_MONTH[month - 1];
  if (day > maxDay)
    return false;
  if (second === 60 && !(hour === 23 && minute === 59 && day === maxDay))
    return false;
  return true;
}
function isCanonicalQuantity(value) {
  if (typeof value !== "string" || !DECIMAL.test(value))
    return false;
  try {
    return BigInt(value) <= MAX_QUANTITY;
  } catch {
    return false;
  }
}
function failure(code, message) {
  return { code, message };
}
function validateAuthorityDelegationShape(value) {
  const failures = [];
  const top = record(snapshotPlainData(value));
  if (!top)
    return [failure("SCHEMA_INVALID", "delegation must be an exact closed v1 object")];
  if (typeof top.record_type !== "string" || typeof top.version !== "string") {
    return [failure("SCHEMA_INVALID", "record_type and version must be strings")];
  }
  if (top.record_type !== AUTHORITY_DELEGATION_RECORD_TYPE) {
    return [failure("UNSUPPORTED_RECORD_TYPE", "record_type names another record, not judged by this schema")];
  }
  if (top.version !== AUTHORITY_DELEGATION_VERSION) {
    return [failure("UNSUPPORTED_VERSION", "unsupported authority-delegation version")];
  }
  if (!exactKeys(top, [
    "record_type",
    "version",
    "delegation_id",
    "parent_delegation_id",
    "issuer",
    "subject",
    "verification_method",
    "issued_at",
    "nonce",
    "authority",
    "signature"
  ]))
    return [failure("SCHEMA_INVALID", "delegation must be an exact closed v1 object")];
  if (!recordStringsAreIJSON(top)) {
    failures.push(failure("SCHEMA_INVALID", "record strings must be I-JSON: no unpaired surrogates or noncharacters"));
  }
  if (typeof top.delegation_id !== "string" || !ID.test(top.delegation_id)) {
    failures.push(failure("SCHEMA_INVALID", "delegation_id must be sha256:<64 lowercase hex>"));
  }
  if (top.parent_delegation_id !== null && (typeof top.parent_delegation_id !== "string" || !ID.test(top.parent_delegation_id))) {
    failures.push(failure("SCHEMA_INVALID", "parent_delegation_id must be null or a delegation digest"));
  }
  for (const key of ["issuer", "subject", "verification_method"]) {
    const item = top[key];
    if (typeof item !== "string" || item.length === 0) {
      failures.push(failure("SCHEMA_INVALID", `${key} must be a non-empty well-formed Unicode string`));
    } else if (Buffer.byteLength(item, "utf8") > 1024) {
      failures.push(failure("RESOURCE_LIMIT", `${key} exceeds this implementation's 1024-byte ceiling`));
    }
  }
  if (!isCanonicalTimestamp(top.issued_at))
    failures.push(failure("NONCANONICAL_VALUE", "issued_at must be canonical UTC milliseconds"));
  if (typeof top.nonce !== "string" || !HEX_32.test(top.nonce))
    failures.push(failure("NONCANONICAL_VALUE", "nonce must be 32 lowercase hex characters"));
  if (typeof top.signature !== "string" || !HEX_128.test(top.signature))
    failures.push(failure("SCHEMA_INVALID", "signature must be 128 lowercase hex characters"));
  const authority = record(top.authority);
  if (!authority || !exactKeys(authority, ["scope", "spend", "depth", "time", "reputation", "values", "reversibility"])) {
    failures.push(failure("SCHEMA_INVALID", "authority must carry exactly all seven facets"));
    return failures;
  }
  const scope = record(authority.scope);
  if (!scope || typeof scope.profile !== "string") {
    failures.push(failure("SCHEMA_INVALID", "scope must contain profile and grants"));
  } else if (scope.profile !== SCOPE_PROFILE_V1) {
    failures.push(failure("UNSUPPORTED_PROFILE", "unsupported scope profile"));
  } else if (!exactKeys(scope, ["profile", "grants"]) || !Array.isArray(scope.grants) || !scope.grants.every((item) => typeof item === "string")) {
    failures.push(failure("SCHEMA_INVALID", "scope must contain profile and grants"));
  } else if (!grantsAreCanonical(scope.grants)) {
    failures.push(failure("NONCANONICAL_VALUE", "scope grants must be valid, sorted, unique, and irredundant"));
  }
  const spend = record(authority.spend);
  if (!spend || typeof spend.mode !== "string") {
    failures.push(failure("SCHEMA_INVALID", "spend must be a tagged object"));
  } else if (spend.mode === "unbounded") {
    if (!exactKeys(spend, ["mode"]))
      failures.push(failure("SCHEMA_INVALID", "unbounded spend has no other fields"));
  } else if (spend.mode === "bounded") {
    if (!exactKeys(spend, ["mode", "unit", "per_action", "cumulative"]) || !isAdmissibleIdentifier(spend.unit) || !isCanonicalQuantity(spend.per_action) || !isCanonicalQuantity(spend.cumulative)) {
      failures.push(failure("NONCANONICAL_VALUE", "bounded spend fields are malformed"));
    } else if (BigInt(spend.per_action) > BigInt(spend.cumulative)) {
      failures.push(failure("SCHEMA_INVALID", "spend per_action cannot exceed cumulative"));
    }
  } else
    failures.push(failure("SCHEMA_INVALID", "unknown spend mode"));
  const depth = record(authority.depth);
  if (!depth || !exactKeys(depth, ["remaining"]) || !Number.isInteger(depth.remaining) || depth.remaining < 0 || depth.remaining > 255) {
    failures.push(failure("SCHEMA_INVALID", "depth.remaining must be an integer from 0 through 255"));
  }
  const time = record(authority.time);
  if (!time || !exactKeys(time, ["not_before", "not_after"]) || !isCanonicalTimestamp(time.not_before) || !isCanonicalTimestamp(time.not_after)) {
    failures.push(failure("NONCANONICAL_VALUE", "time bounds must be canonical UTC milliseconds"));
  } else if (time.not_before >= time.not_after) {
    failures.push(failure("SCHEMA_INVALID", "time window must be non-empty"));
  } else if (top.parent_delegation_id !== null && isCanonicalTimestamp(top.issued_at) && time.not_before < top.issued_at) {
    failures.push(failure("SCHEMA_INVALID", "time.not_before cannot predate issued_at"));
  }
  const reputation = record(authority.reputation);
  if (!reputation || typeof reputation.profile !== "string") {
    failures.push(failure("SCHEMA_INVALID", "reputation ceiling must be an integer from 0 through 100"));
  } else if (reputation.profile !== REPUTATION_PROFILE_V1) {
    failures.push(failure("UNSUPPORTED_PROFILE", "unsupported reputation profile"));
  } else if (!exactKeys(reputation, ["profile", "ceiling"]) || !Number.isInteger(reputation.ceiling) || reputation.ceiling < 0 || reputation.ceiling > 100) {
    failures.push(failure("SCHEMA_INVALID", "reputation ceiling must be an integer from 0 through 100"));
  }
  const values = record(authority.values);
  if (!values || typeof values.profile !== "string") {
    failures.push(failure("SCHEMA_INVALID", "values.required must contain valid identifiers"));
  } else if (values.profile !== VALUES_PROFILE_V1) {
    failures.push(failure("UNSUPPORTED_PROFILE", "unsupported values profile"));
  } else if (!exactKeys(values, ["profile", "required"]) || !Array.isArray(values.required) || !values.required.every(isAdmissibleIdentifier)) {
    failures.push(failure("SCHEMA_INVALID", "values.required must contain valid identifiers"));
  } else {
    const required = values.required;
    if (required.some((item, i) => i > 0 && required[i - 1] >= item)) {
      failures.push(failure("NONCANONICAL_VALUE", "values.required must be sorted and unique"));
    }
  }
  const reversibility = record(authority.reversibility);
  if (!reversibility || typeof reversibility.profile !== "string") {
    failures.push(failure("SCHEMA_INVALID", "reversibility facet is malformed"));
  } else if (reversibility.profile !== REVERSIBILITY_PROFILE_V1) {
    failures.push(failure("UNSUPPORTED_PROFILE", "unsupported reversibility profile"));
  } else if (!exactKeys(reversibility, ["profile", "ceiling"]) || typeof reversibility.ceiling !== "string" || !["tentative", "compensable", "irreversible"].includes(reversibility.ceiling)) {
    failures.push(failure("SCHEMA_INVALID", "reversibility facet is malformed"));
  }
  return failures;
}

// verifier/node_modules/agent-passport-system/dist/src/v2/authority-delegation/compare.js
var REVERSIBILITY_RANK = {
  tentative: 0,
  compensable: 1,
  irreversible: 2
};
function reversibilityRank(ceiling) {
  if (typeof ceiling !== "string")
    return null;
  const rank = REVERSIBILITY_RANK[ceiling];
  return rank === void 0 ? null : rank;
}
function fail(failures, code, facet, message) {
  failures.push({ code, facet, message });
}
function compareAuthority(parent, child) {
  const failures = [];
  if (child.scope.profile !== parent.scope.profile) {
    fail(failures, "UNSUPPORTED_PROFILE", "scope", "scope profile changes are incomparable");
  } else if (!scopeNarrows(parent.scope.grants, child.scope.grants)) {
    fail(failures, "SCOPE_WIDENING", "scope", "child scope is not covered by parent scope");
  }
  if (parent.spend.mode === "bounded") {
    if (child.spend.mode === "unbounded") {
      fail(failures, "SPEND_WIDENING", "spend", "bounded parent cannot produce unbounded child");
    } else if (child.spend.unit !== parent.spend.unit) {
      fail(failures, "SPEND_UNIT_CHANGE", "spend", "bounded spend unit must remain exact");
    } else if (BigInt(child.spend.per_action) > BigInt(parent.spend.per_action) || BigInt(child.spend.cumulative) > BigInt(parent.spend.cumulative)) {
      fail(failures, "SPEND_WIDENING", "spend", "child spend limits exceed parent limits");
    }
  }
  if (parent.depth.remaining === 0) {
    fail(failures, "DEPTH_EXHAUSTED", "depth", "parent has no remaining delegation hop");
  } else if (child.depth.remaining > parent.depth.remaining - 1) {
    fail(failures, "DEPTH_WIDENING", "depth", "child remaining depth must consume at least one hop");
  }
  if (child.time.not_before < parent.time.not_before || child.time.not_after > parent.time.not_after) {
    fail(failures, "TIME_WIDENING", "time", "child validity window is not contained in parent window");
  }
  if (child.reputation.profile !== parent.reputation.profile) {
    fail(failures, "UNSUPPORTED_PROFILE", "reputation", "reputation profile changes are incomparable");
  } else if (child.reputation.ceiling > parent.reputation.ceiling) {
    fail(failures, "REPUTATION_WIDENING", "reputation", "child reputation ceiling exceeds parent");
  }
  if (child.values.profile !== parent.values.profile) {
    fail(failures, "UNSUPPORTED_PROFILE", "values", "values profile changes are incomparable");
  } else {
    const childRequired = new Set(child.values.required);
    if (parent.values.required.some((identifier) => !childRequired.has(identifier))) {
      fail(failures, "VALUES_WEAKENING", "values", "child removed an ancestor-required value identifier");
    }
  }
  if (child.reversibility.profile !== parent.reversibility.profile) {
    fail(failures, "UNSUPPORTED_PROFILE", "reversibility", "reversibility profile changes are incomparable");
  } else {
    const childRank = reversibilityRank(child.reversibility.ceiling);
    const parentRank = reversibilityRank(parent.reversibility.ceiling);
    if (childRank === null || parentRank === null || childRank > parentRank) {
      fail(failures, "REVERSIBILITY_WIDENING", "reversibility", "child reversibility ceiling exceeds parent");
    }
  }
  return failures;
}

// verifier/node_modules/agent-passport-system/dist/src/v2/authority-delegation/verify.js
function result(state, failures) {
  return { state, valid: state === "valid", failures };
}
function indexed(failure2, index) {
  return { ...failure2, index };
}
var KEY_MATERIAL = /^[0-9a-fA-F]{64}$/;
function keyResolutionFailure(resolved) {
  if (typeof resolved === "string") {
    return KEY_MATERIAL.test(resolved) ? null : { state: "indeterminate", code: "KEY_MATERIAL_MALFORMED", message: "resolved key material is not a 32-byte Ed25519 public key" };
  }
  if (resolved && typeof resolved === "object" && typeof resolved.outcome === "string") {
    switch (resolved.outcome) {
      case "unsupported_scheme":
        return { state: "unsupported", code: "KEY_SCHEME_UNSUPPORTED", message: "identifier scheme is not supported by the resolver" };
      case "not_found":
        return { state: "indeterminate", code: "KEY_NOT_FOUND", message: "subject or key was not found" };
      case "ambiguous":
        return { state: "indeterminate", code: "KEY_AMBIGUOUS", message: "key resolution was ambiguous" };
      case "unreachable":
        return { state: "indeterminate", code: "KEY_UNREACHABLE", message: "key material was unreachable" };
      case "malformed":
        return { state: "indeterminate", code: "KEY_MATERIAL_MALFORMED", message: "resolved key material is structurally malformed" };
      default:
        break;
    }
  }
  return { state: "indeterminate", code: "KEY_RESOLUTION_FAILED", message: "issuer verification key could not be resolved" };
}
var UNSUPPORTED_CODES = /* @__PURE__ */ new Set(["UNSUPPORTED_VERSION", "UNSUPPORTED_RECORD_TYPE", "UNSUPPORTED_PROFILE"]);
function shapeState(failures) {
  if (failures.some((item) => !UNSUPPORTED_CODES.has(item.code) && item.code !== "RESOURCE_LIMIT"))
    return "invalid";
  if (failures.some((item) => UNSUPPORTED_CODES.has(item.code)))
    return "unsupported";
  return "indeterminate";
}
function verifyAuthorityDelegationChain(rawChain, options2) {
  const rejection = { reason: "not-a-container" };
  const container = readPlainDataChainContainer(rawChain, 1, 256, rejection);
  if (!container) {
    return rejection.reason === "over-ceiling" ? result("indeterminate", [{ code: "RESOURCE_LIMIT", message: "chain exceeds this implementation's 256-record ceiling" }]) : result("invalid", [{ code: "SCHEMA_INVALID", message: "chain must be a container of at least one record" }]);
  }
  const read = (key) => {
    try {
      return options2 ? options2[key] : void 0;
    } catch {
      return void 0;
    }
  };
  const now = read("now");
  const trustRoot = read("trustRoot");
  const resolveVerificationKey = read("resolveVerificationKey");
  const resolveRevocation = read("resolveRevocation");
  if (!isCanonicalTimestamp(now)) {
    return result("invalid", [{ code: "NONCANONICAL_VALUE", message: "verification clock must be canonical UTC milliseconds" }]);
  }
  const chain = [];
  for (let i = 0; i < container.length; i++) {
    const snapshot = snapshotPlainData(container[i]);
    const failures = validateAuthorityDelegationShape(snapshot).map((item) => indexed(item, i));
    if (failures.length > 0) {
      return result(shapeState(failures), failures);
    }
    chain.push(snapshot);
  }
  for (let i = 0; i < chain.length; i++) {
    const delegation = chain[i];
    if (computeAuthorityDelegationId(authorityDelegationBody(delegation)) !== delegation.delegation_id) {
      return result("invalid", [{ code: "ID_MISMATCH", index: i, message: "delegation content address does not match body" }]);
    }
  }
  for (let i = 0; i < chain.length; i++) {
    const delegation = chain[i];
    let resolved = null;
    try {
      resolved = resolveVerificationKey(delegation.issuer, delegation.verification_method, delegation.issued_at);
    } catch {
      resolved = null;
    }
    const failure2 = keyResolutionFailure(resolved);
    if (failure2)
      return result(failure2.state, [{ code: failure2.code, index: i, message: failure2.message }]);
    if (!verifyAuthorityDelegationSignature(delegation, resolved)) {
      return result("invalid", [{ code: "SIGNATURE_INVALID", index: i, message: "Ed25519 signature is invalid" }]);
    }
  }
  const seen = /* @__PURE__ */ new Set();
  for (let i = 0; i < chain.length; i++) {
    const id = chain[i].delegation_id;
    if (seen.has(id)) {
      return result("invalid", [{ code: "CHAIN_DUPLICATE_ID", index: i, message: "delegation ID repeats in chain" }]);
    }
    seen.add(id);
  }
  const root = chain[0];
  if (typeof trustRoot !== "function") {
    return result("indeterminate", [{ code: "ROOT_UNTRUSTED", index: 0, message: "root trust policy is unavailable" }]);
  }
  let trustDecision;
  try {
    trustDecision = trustRoot(snapshotPlainData(root));
  } catch {
    return result("indeterminate", [{ code: "ROOT_UNTRUSTED", index: 0, message: "root trust policy could not decide" }]);
  }
  if (typeof trustDecision !== "boolean") {
    return result("indeterminate", [{ code: "ROOT_UNTRUSTED", index: 0, message: "root trust policy returned no boolean decision" }]);
  }
  if (!trustDecision) {
    return result("invalid", [{ code: "ROOT_UNTRUSTED", index: 0, message: "root is not accepted by verifier trust policy" }]);
  }
  if (root.parent_delegation_id !== null) {
    return result("invalid", [{ code: "PARENT_MISMATCH", index: 0, message: "full chain root must carry null parent_delegation_id" }]);
  }
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].parent_delegation_id !== chain[i - 1].delegation_id) {
      return result("invalid", [{ code: "PARENT_MISMATCH", index: i, message: "child does not name immediate parent content address" }]);
    }
  }
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].issuer !== chain[i - 1].subject) {
      return result("invalid", [{ code: "CHAIN_CONTINUITY", index: i, message: "child issuer is not parent subject" }]);
    }
  }
  for (let i = 1; i < chain.length; i++) {
    const parent = chain[i - 1];
    const issued = chain[i].issued_at;
    if (issued < parent.authority.time.not_before || issued >= parent.authority.time.not_after) {
      return result("invalid", [{ code: "ISSUED_AT_OUTSIDE_PARENT", index: i, message: "child was issued outside parent validity window" }]);
    }
  }
  for (let i = 1; i < chain.length; i++) {
    const attenuationFailures = compareAuthority(chain[i - 1].authority, chain[i].authority);
    if (attenuationFailures.length > 0) {
      const indexedFailures = attenuationFailures.map((item) => indexed(item, i));
      const unsupported = indexedFailures.every((item) => item.code === "UNSUPPORTED_PROFILE");
      return result(unsupported ? "unsupported" : "invalid", indexedFailures);
    }
  }
  for (let i = 0; i < chain.length; i++) {
    const time = chain[i].authority.time;
    if (now < time.not_before) {
      return result("invalid", [{ code: "NOT_YET_VALID", index: i, message: "delegation is not yet valid" }]);
    }
    if (now >= time.not_after) {
      return result("invalid", [{ code: "EXPIRED", index: i, message: "delegation has expired" }]);
    }
  }
  for (let i = 0; i < chain.length; i++) {
    let revocation = "unknown";
    try {
      const resolved = resolveRevocation(snapshotPlainData(chain[i]));
      revocation = resolved === "active" || resolved === "revoked" ? resolved : "unknown";
    } catch {
      revocation = "unknown";
    }
    if (revocation === "revoked") {
      return result("invalid", [{ code: "REVOKED", index: i, message: "delegation is revoked" }]);
    }
    if (revocation === "unknown") {
      return result("indeterminate", [{ code: "REVOCATION_UNKNOWN", index: i, message: "revocation status is unknown" }]);
    }
  }
  return result("valid", []);
}

// verifier/node_modules/agent-passport-system/dist/src/v2/chain-selection/types.js
var HELD_SET_CEILING = 256;

// verifier/node_modules/agent-passport-system/dist/src/v2/chain-selection/select.js
var ACTION_REF2 = /^[0-9a-f]{64}$/;
var QUANTITY = /^(0|[1-9][0-9]*)$/;
function readHeldSet(held) {
  let entries;
  try {
    if (!Array.isArray(held))
      return "held_set_empty";
    if (held.length > HELD_SET_CEILING)
      return "held_set_over_ceiling";
    if (held.length < 1)
      return "held_set_empty";
    entries = Array.prototype.slice.call(held);
  } catch {
    return "held_set_empty";
  }
  const output = [];
  const seen = /* @__PURE__ */ new Set();
  for (const entry of entries) {
    let chainId;
    let chain;
    try {
      if (entry === null || typeof entry !== "object")
        return "held_chain_malformed";
      chainId = entry.chain_id;
      chain = entry.chain;
    } catch {
      return "held_chain_malformed";
    }
    if (typeof chainId !== "string" || chainId.length === 0)
      return "held_chain_malformed";
    if (chain === void 0)
      return "held_chain_malformed";
    if (seen.has(chainId))
      return "duplicate_chain_id";
    seen.add(chainId);
    output.push({ chain_id: chainId, chain });
  }
  return output;
}
function readRequirement(requiredGrants, requiredSpend) {
  let grants;
  try {
    if (!Array.isArray(requiredGrants))
      return null;
    grants = Array.prototype.slice.call(requiredGrants);
  } catch {
    return null;
  }
  const needed = [];
  for (const grant of grants) {
    if (typeof grant !== "string" || !isValidScopeGrant(grant))
      return null;
    needed.push(grant);
  }
  if (requiredSpend === void 0 || requiredSpend === null)
    return { grants: needed, spend: null };
  let unit;
  let amount;
  let actionRef;
  try {
    if (typeof requiredSpend !== "object")
      return null;
    unit = requiredSpend.unit;
    amount = requiredSpend.amount;
    actionRef = requiredSpend.action_ref;
  } catch {
    return null;
  }
  if (typeof unit !== "string" || unit.length === 0)
    return null;
  if (typeof amount !== "string" || !QUANTITY.test(amount))
    return null;
  if (typeof actionRef !== "string" || !ACTION_REF2.test(actionRef))
    return null;
  return { grants: needed, spend: { unit, amount, action_ref: actionRef } };
}
function evaluateHeldChain(entry, needed, spend, input, reserveBudget) {
  const refuse = (code, chainState) => ({
    evaluation: { chain_id: entry.chain_id, outcome: "refuses", code, chain_state: chainState },
    result: null
  });
  const undecided = (code, chainState) => ({
    evaluation: { chain_id: entry.chain_id, outcome: "undecided", code, chain_state: chainState },
    result: null
  });
  const rejection = { reason: "not-a-container" };
  const container = readPlainDataChainContainer(entry.chain, 1, 256, rejection);
  if (!container) {
    const result3 = verifyAuthorityDelegationChain(Array.isArray(entry.chain) ? entry.chain : [], input.options);
    const code = result3.failures[0]?.code ?? "SCHEMA_INVALID";
    return result3.state === "invalid" ? refuse(code, result3.state) : undecided(code, result3.state);
  }
  const records = container.map((member) => snapshotPlainData(member));
  for (let i = 1; i < records.length; i++) {
    const member = records[i];
    if (member !== null && typeof member === "object" && member.parent_delegation_id === null) {
      return refuse("chain_set_presented_as_one", null);
    }
  }
  const result2 = verifyAuthorityDelegationChain(records, input.options);
  if (result2.state !== "valid") {
    const code = result2.failures[0]?.code ?? result2.state;
    return result2.state === "invalid" ? refuse(code, result2.state) : undecided(code, result2.state);
  }
  const leaf = records[records.length - 1];
  const grants = leaf.authority.scope.grants;
  for (const want of needed) {
    if (!grants.some((grant) => scopeGrantCovers(grant, want))) {
      return refuse("scope_not_covered", result2.state);
    }
  }
  if (!spend) {
    return {
      evaluation: { chain_id: entry.chain_id, outcome: "authorizes", code: "scope_covered", chain_state: result2.state },
      result: result2
    };
  }
  if (!reserveBudget) {
    return undecided("spend_ledger_unavailable", result2.state);
  }
  let reservation;
  try {
    reservation = reserveBudget.reserve(records, spend.action_ref, spend.unit, spend.amount);
  } catch {
    return undecided("spend_ledger_unavailable", result2.state);
  }
  if (!reservation || typeof reservation !== "object" || typeof reservation.code !== "string") {
    return undecided("spend_ledger_unavailable", result2.state);
  }
  if (reservation.ok !== true) {
    return refuse(reservation.code, result2.state);
  }
  return {
    evaluation: { chain_id: entry.chain_id, outcome: "authorizes", code: reservation.code, chain_state: result2.state },
    result: result2
  };
}
function failureFor(evaluations) {
  if (evaluations.some((item) => item.outcome === "undecided"))
    return "selection_undecided";
  return evaluations.some((item) => item.chain_state === "valid") ? "no_chain_covers_action" : "no_valid_chain";
}
function fail2(code, evaluations) {
  return { selected: false, chain_id: null, code, evaluations };
}
function selectChainForAction(input) {
  const held = readHeldSet(input?.held);
  if (typeof held === "string")
    return fail2(held, []);
  const requirement = readRequirement(input?.requiredGrants, input?.requiredSpend);
  if (!requirement)
    return fail2("invalid_action_requirement", []);
  const reserveBudget = input?.reserveBudget ?? null;
  const evaluations = [];
  let chosen = null;
  let chosenResult = null;
  for (const entry of held) {
    const evaluated = evaluateHeldChain(entry, requirement.grants, null, input, null);
    evaluations.push(evaluated.evaluation);
    if (evaluated.evaluation.outcome === "authorizes") {
      chosen = entry;
      chosenResult = evaluated.result;
      break;
    }
  }
  if (!chosen || !chosenResult)
    return fail2(failureFor(evaluations), evaluations);
  if (!requirement.spend) {
    return { selected: true, chain_id: chosen.chain_id, result: chosenResult, evaluations };
  }
  const admitted = evaluateHeldChain(chosen, requirement.grants, requirement.spend, input, reserveBudget);
  evaluations[evaluations.length - 1] = admitted.evaluation;
  if (admitted.evaluation.outcome !== "authorizes" || !admitted.result) {
    return fail2(failureFor(evaluations), evaluations);
  }
  return { selected: true, chain_id: chosen.chain_id, result: admitted.result, evaluations };
}

// verifier/node_modules/agent-passport-system/dist/src/v2/authority-revocation/canonical.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/lifecycle-state/state.js
var ESTABLISHED_NEGATIVE_RESOLUTIONS = Object.freeze({
  enabling_condition_not_yet_occurred: Object.freeze({
    shape: "enabling_condition_not_yet_occurred",
    subject: "artifact",
    verdict: "not_yet_effective",
    reason_code: "ENABLING_CONDITION_NOT_YET_OCCURRED"
  }),
  composition_not_satisfied: Object.freeze({
    shape: "composition_not_satisfied",
    subject: "boundary",
    outcome: "denied",
    reason_code: "COMPOSITION_NOT_SATISFIED"
  }),
  pinned_referent_mismatch: Object.freeze({
    shape: "pinned_referent_mismatch",
    subject: "boundary",
    outcome: "denied",
    reason_code: "PINNED_REFERENT_MISMATCH"
  })
});

// verifier/node_modules/agent-passport-system/dist/src/v2/lifecycle-state/map.js
var GAPS_BY_CODE = Object.freeze({
  // The resolver answered `unknown`: no accepted source produced a usable determinate answer.
  REVOCATION_UNKNOWN: Object.freeze(["source"]),
  KEY_RESOLUTION_FAILED: Object.freeze(["source"]),
  KEY_NOT_FOUND: Object.freeze(["source"]),
  KEY_AMBIGUOUS: Object.freeze(["source"]),
  KEY_UNREACHABLE: Object.freeze(["source"]),
  KEY_MATERIAL_MALFORMED: Object.freeze(["source"]),
  KEY_SCHEME_UNSUPPORTED: Object.freeze(["source"]),
  // A ceiling this implementation imposes: it declined to judge the whole record, so what
  // the answer does not cover is the record itself.
  RESOURCE_LIMIT: Object.freeze(["coverage"]),
  UNSUPPORTED_VERSION: Object.freeze(["source"]),
  UNSUPPORTED_RECORD_TYPE: Object.freeze(["source"]),
  UNSUPPORTED_PROFILE: Object.freeze(["source"])
});
var DEFAULT_GAPS = Object.freeze(["source"]);

// verifier/node_modules/agent-passport-system/dist/src/v2/activation/types.js
var ACTIVATION_GAPS_BY_REASON = Object.freeze({
  CONDITION_DELEGATION_MISMATCH: Object.freeze(["coverage"]),
  ATTESTATION_DOES_NOT_REACH_ACTION: Object.freeze(["coverage"])
});

// verifier/node_modules/agent-passport-system/dist/src/v2/activation/canonical.js
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/activation/verify.js
init_rfc3339();
init_keys();
var REJECTION_RANK = Object.freeze({
  ATTESTATION_RECORD_TYPE_NOT_ACCEPTED: 1,
  ATTESTATION_SIGNATURE_UNVERIFIED: 2,
  ATTESTATION_ATTESTOR_BINDING_MISMATCH: 3,
  ATTESTATION_ATTESTOR_ROLE_UNKNOWN: 4,
  ATTESTATION_ROLE_CLAIM_CONFLICT: 5,
  ATTESTATION_ATTESTOR_ROLE_MISMATCH: 6,
  ATTESTATION_CONDITION_MISMATCH: 7,
  ATTESTATION_UNKNOWN_ASSERTION: 8,
  ATTESTATION_INSTANT_MALFORMED: 9,
  ATTESTATION_DOES_NOT_REACH_ACTION: 10,
  // Verdict-level codes never rank: they are not rejections of a record.
  ACTIVATION_ESTABLISHED: 0,
  CONDITION_DATE_NOT_REACHED: 0,
  CONDITION_ESTABLISHED_NOT_YET_OCCURRED: 0,
  CONDITION_FIRST_OCCURRED_AFTER_ACTION: 0,
  CONDITION_EVIDENCE_CONFLICT: 0,
  ACTIVATION_THRESHOLD_NOT_MET: 0,
  NO_ATTESTATION_PRESENTED: 0,
  CONDITION_DELEGATION_MISMATCH: 0
});

// verifier/node_modules/agent-passport-system/dist/src/v2/bounds/canonical.js
init_canonical_jcs();
init_keys();

// verifier/node_modules/agent-passport-system/dist/src/v2/capability-binding/digest.js
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/capability-binding/identifier.js
init_keys();
init_canonical_jcs();

// verifier/node_modules/agent-passport-system/dist/src/v2/status-coverage/decide.js
init_rfc3339();

// verifier/node_modules/agent-passport-system/dist/src/v2/suspension/evaluate.js
init_canonical_jcs();
init_keys();

// verifier/ot-scope.mjs
var PROFILE = "ot-scope/v1";
var NAMESPACE = "ot";
var FIELDS = ["building_id", "asset", "parameter", "operation"];
var SEGMENT = /^[\x21-\x7e]+$/;
function segmentProblem(value) {
  if (typeof value !== "string" || value.length === 0) return "empty or not a string";
  if (!SEGMENT.test(value)) return "not printable ASCII";
  if (value.includes(":")) return 'contains ":"';
  if (value.includes("*")) return 'contains "*"';
  return null;
}
function grantForCall(call) {
  for (const f of FIELDS) {
    const p = segmentProblem(call?.[f]);
    if (p) throw new Error(`${f} ${p}`);
  }
  const grant = [NAMESPACE, ...FIELDS.map((f) => call[f])].join(":");
  if (!isValidScopeGrant(grant)) throw new Error("not a valid aps-hierarchical-v1 grant");
  return grant;
}
function isExactGrant(grant) {
  return typeof grant === "string" && !grant.includes("*");
}
function toApsTime(t) {
  if (typeof t !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(t))
    throw new Error(`decision_time is not YYYY-MM-DDTHH:MM:SSZ: ${JSON.stringify(t)}`);
  return t.slice(0, -1) + ".000Z";
}
function b64urlToHex(s) {
  return Buffer.from(s, "base64url").toString("hex");
}

// verifier/verify.mjs
var HERE = dirname(fileURLToPath(import.meta.url));
var EDGE_ID = "aps-authority-verifier";
var SDK_VERSION = true ? "8.0.1" : JSON.parse(readFileSync(join(HERE, "node_modules/agent-passport-system/package.json"), "utf8")).version;
var TRUST = JSON.parse(readFileSync(join(HERE, "trust.json"), "utf8"));
var ROOTS = TRUST.root_verification_methods;
var SIGNERS = { ...TRUST.signer_verification_methods, ...ROOTS };
function options(now) {
  return {
    now,
    resolveVerificationKey(issuer, verificationMethod) {
      if (!verificationMethod.startsWith(issuer + "#")) return { outcome: "not_found" };
      const key = SIGNERS[verificationMethod];
      return key ? b64urlToHex(key) : { outcome: "not_found" };
    },
    trustRoot: (root) => Object.hasOwn(ROOTS, root.verification_method) && root.verification_method.startsWith(root.issuer + "#"),
    // The fixture sets carry no revocation evidence. Test policy: every member is active.
    resolveRevocation: () => "active"
  };
}
function decide(call, chain) {
  let grant, now;
  try {
    grant = grantForCall(call);
  } catch (e) {
    return { verdict: "refuse", reason: `ot_call_unencodable: ${e.message}` };
  }
  try {
    now = toApsTime(call.decision_time);
  } catch (e) {
    return { verdict: "refuse", reason: `ot_decision_time_malformed: ${e.message}` };
  }
  const opts = options(now);
  const sel = selectChainForAction({ held: [{ chain_id: "presented", chain }], requiredGrants: [grant], options: opts });
  const aps = { required_grant: grant, now, selected: sel.selected };
  if (!sel.selected) {
    const ev = sel.evaluations[0];
    aps.selection_code = sel.code;
    if (!ev) return { verdict: "refuse", reason: sel.code, aps };
    Object.assign(aps, { evaluation_outcome: ev.outcome, code: ev.code, chain_state: ev.chain_state });
    let detail = "";
    if (ev.chain_state && ev.chain_state !== "valid") {
      const f = verifyAuthorityDelegationChain(chain, opts).failures[0];
      if (f) detail = `@${f.index ?? "-"}: ${f.message}`;
    } else if (ev.code === "scope_not_covered") {
      detail = `: leaf does not grant ${grant}`;
    }
    if (ev.outcome === "undecided") return { verdict: "indeterminate", reason: `${ev.code}${detail}`, aps };
    return { verdict: "refuse", reason: `${ev.code}${detail}`, aps };
  }
  for (let i = 0; i < chain.length; i++) {
    const bad = chain[i].authority.scope.grants.find((g) => !isExactGrant(g));
    if (bad !== void 0) return { verdict: "refuse", reason: `ot_wildcard_grant@${i}: ${bad}`, aps };
  }
  aps.code = sel.evaluations[0].code;
  aps.chain_state = sel.result.state;
  return { verdict: "pass", reason: `${aps.code}: chain valid at ${now}, leaf grants ${grant}`, aps };
}
function run(fixtures, out) {
  const manifest = JSON.parse(readFileSync(join(fixtures, "manifest.json"), "utf8"));
  const verdicts = [];
  for (const { case_id } of manifest.cases) {
    let v;
    try {
      const c = JSON.parse(readFileSync(join(fixtures, "cases", `${case_id}.json`), "utf8"));
      v = decide(c.call, c.delegation);
    } catch (e) {
      v = { verdict: "error", reason: `${e?.name ?? "Error"}: ${e?.message ?? e}` };
    }
    verdicts.push({ case_id, ...v });
  }
  writeFileSync(out, JSON.stringify({
    schema: "ot-authority-verifier-result/v1",
    edge_id: EDGE_ID,
    verifier_revision: `agent-passport-system@${SDK_VERSION}; ${PROFILE}`,
    verdicts
  }, null, 2) + "\n", "utf8");
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [cmd, ...rest] = process.argv.slice(2);
  const arg = (name) => {
    const i = rest.indexOf(name);
    return i >= 0 ? rest[i + 1] : void 0;
  };
  if (cmd !== "run" || !arg("--fixtures") || !arg("--out")) {
    process.stderr.write("usage: verify.mjs run --fixtures <set dir> --out <result.json>\n");
    process.exit(2);
  }
  run(arg("--fixtures"), arg("--out"));
}
export {
  decide
};
