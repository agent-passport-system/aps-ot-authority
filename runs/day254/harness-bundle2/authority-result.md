# authority_fixture: `aps-1` with `aps`

Result: **PASS**. Verifier Agent Passport System: ok, 226.2 ms. Package `sha256:cf5cdbf3345b844df6254314f02de001ed3d4ba2141b76355b068d40a26240d6`.

Delegation check as expected 5/5; work-order check as expected 5/5; oracle agrees 5/5; admitted 1. Verifier answers by class: answered 5, error 0, timeout 0, malformed 0, unanswered 0.

| Case | Built as | Delegation check (expected / got, reason) | Work-order check (expected / got, reasons) | Admitted | Oracle |
|---|---|---|---|---|---|
| `af-1-valid` | owner grants operator ZONE-01 and ZONE-02; operator grants agent ZONE-01 until 18:00; call ZONE-01 at 07:00, 20.5 degC | pass / pass (scope_covered: chain valid at 2026-01-15T07:00:00.000Z, leaf grants ot:demo-building-001:ZONE-01:setpoint_c:set_zone_setpoint) | pass / pass (none) | yes | permitted  |
| `af-2-widened` | operator holds ZONE-01 and ZONE-02 but grants the agent ZONE-01 and ZONE-03 (signed directly; the SDK issuer refuses to widen) | refuse / refuse (SCOPE_WIDENING@1: child scope is not covered by parent scope) | pass / pass (none) | no | forbidden (delegation_invalid) |
| `af-3-expired` | the agent's grant for ZONE-01 ends at 06:00 (not_after, exclusive); the decision time is 07:00 | refuse / refuse (EXPIRED@1: delegation has expired) | pass / pass (none) | no | forbidden (delegation_invalid) |
| `af-4-out-of-scope` | a valid, narrowed chain grants the agent ZONE-02 only; the call is on ZONE-01 | refuse / refuse (scope_not_covered: leaf does not grant ot:demo-building-001:ZONE-01:setpoint_c:set_zone_setpoint) | pass / pass (none) | no | forbidden (delegation_invalid) |
| `af-5-value-out-of-range` | valid chain granting ZONE-01; the value 22.5 is outside the work order's 19.0..21.0, which the delegation does not carry | pass / pass (scope_covered: chain valid at 2026-01-15T07:00:00.000Z, leaf grants ot:demo-building-001:ZONE-01:setpoint_c:set_zone_setpoint) | refuse / refuse (value_above_range) | no | forbidden (outside_work_order) |

Both checks ran on the same captured input. Errors, timeouts, malformed and unanswered verifier answers are their own class: never a refusal, never a catch.
