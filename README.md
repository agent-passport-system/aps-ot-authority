# aps-ot-authority

APS delegations and a delegation verifier for the `authority_fixture` harness of
[darklordVirtual/autonomous-ot-control#27](https://github.com/darklordVirtual/autonomous-ot-control/issues/27).

- `mint/mint.mjs` builds the five cases as `aps:authority-delegation:v1` chains with
  `agent-passport-system@8.0.1` and writes `submission/aps-1/` (`ot-authority-submission/v1`)
  and `verifier/trust.json`.
- `edge/aps/` is what the harness calls: `verifier/verify.mjs` bundled with the SDK into one file, no install step,
  `edge.json` pinning `node:24-slim` by digest. See `edge/aps/README.md`.
- `verifier/` is the source of that bundle: `edge.json`, `verify.mjs run --fixtures <set> --out <result.json>`,
  pinned to `agent-passport-system@8.0.1` by its own `package-lock.json` (`npm ci --prefix verifier`).
- `verifier/ot-scope.mjs` is the scope encoding: one exact grant
  `ot:<building_id>:<asset>:<parameter>:<operation>` per tuple, no wildcards.
- `verifier/selftest.mjs` checks window boundaries, tampering, unencodable calls and wildcards.

**Test-only keys.** Every private key is the SHA-256 of a public label in `mint/mint.mjs`.
Anyone can sign with them. Never trust them anywhere else.

Synthetic, simulator only. A pass from this verifier never authorizes a control action.

```bash
npm ci && npm ci --prefix verifier
node mint/mint.mjs            # needs a clean tree; records HEAD as source.revision
node verifier/selftest.mjs
```
