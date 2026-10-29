# authority_fixture: `aps-2` with `aps`

Profile: **identity-reason/v2**. Manifest SHA-256: `52dce01c394105b5c6a158e0a5facec504f26bb769a1bba70eb4b0e5cd4118fd`.

Result: **PASS**. Verifier Agent Passport System: ok, 39.6 ms. Package `sha256:b1441ee6bf0beb890030a7e42becea24ba3bd2ab89d49546d4012e4006385189`.

Contract problems: none.

Delegation check as expected 5/5; work-order check as expected 5/5; oracle agrees 5/5; admitted 1. Verifier answers by class: answered 5, indeterminate 0, error 0, timeout 0, malformed 0, unanswered 0.

Delegation reasons as expected: 5. Identity bindings as expected: 5.

Complete signed bindings as expected: 5.

| Case | Built as | Delegation check (expected / got, reason) | Work-order check (expected / got, reasons) | Admitted | Oracle |
|---|---|---|---|---|---|
| `af-1-valid` | owner grants operator ZONE-01 and ZONE-02; operator grants agent ZONE-01 until 18:00; call ZONE-01 at 07:00, 20.5 degC | pass / pass (scope_covered; expected reason: scope_covered; reason match: True; identity: sha256:f5cbee1f860f7f58423b2ccdecb4143143dc816942763dc32cebdeb3a3cedd6e; identity match: True) | pass / pass (none) | yes | permitted  |
| `af-2-widened` | operator holds ZONE-01 and ZONE-02 but grants the agent ZONE-01 and ZONE-03 (signed directly; the SDK issuer refuses to widen) | refuse / refuse (SCOPE_WIDENING; expected reason: SCOPE_WIDENING; reason match: True; identity: sha256:3d82edbe46fe8956a777928657c47083fedd858124dea214b8014e13010eefb2; identity match: True) | pass / pass (none) | no | forbidden (delegation_invalid) |
| `af-3-expired` | the agent's grant for ZONE-01 ends at 06:00 (not_after, exclusive); the decision time is 07:00 | refuse / refuse (EXPIRED; expected reason: EXPIRED; reason match: True; identity: sha256:cc660515db7a1ac4830a7522f13707c1f527e4846d4c2fee42d1e0cb9ffbc64d; identity match: True) | pass / pass (none) | no | forbidden (delegation_invalid) |
| `af-4-out-of-scope` | a valid, narrowed chain grants the agent ZONE-02 only; the call is on ZONE-01 | refuse / refuse (scope_not_covered; expected reason: scope_not_covered; reason match: True; identity: sha256:3f1868e184a5b8ba1e6709554bc3461296ddfca00eb10e33457861edfb7b2439; identity match: True) | pass / pass (none) | no | forbidden (delegation_invalid) |
| `af-5-value-out-of-range` | valid chain granting ZONE-01; the value 22.5 is outside the work order's 19.0..21.0, which the delegation does not carry | pass / pass (scope_covered; expected reason: scope_covered; reason match: True; identity: sha256:4208956f10743a127a3ebd2387839132077e08c04a4ae457c8ab4a4c48adf6e8; identity match: True) | refuse / refuse (value_above_range) | no | forbidden (outside_work_order) |

Both checks ran on the same captured input. Indeterminate, errors, timeouts, malformed and unanswered verifier answers are separate classes: never a refusal, never a catch. Strict identity/reason evaluation; no runtime authorization or physical control.

