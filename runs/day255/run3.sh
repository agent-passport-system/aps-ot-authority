#!/bin/zsh
export PATH="/opt/homebrew/bin:$HOME/.local/bin:$PATH"
A=~/work/aps-ot-authority; T=~/work/ot-pr38; O=$A/runs/day255
cd $T
echo '$ strict profile on the legacy aps-1 set (expected: not a pass)'
python3 -m runner.authority_harness --fixtures $A/runs/fixtures/aps-1 --verifier $A/edge/aps --out $O/harness-aps-1-strict --timeout 120 --trust-edge aps 2>&1 | head -12; echo "harness exit=${pipestatus[1]}"
echo '$ legacy verdict-only on aps-1 with the new edge'
python3 -m runner.authority_harness --fixtures $A/runs/fixtures/aps-1 --verifier $A/edge/aps --out $O/harness-aps-1-legacy --timeout 120 --trust-edge aps --legacy-verdict-only 2>&1 | head -8; echo "harness exit=${pipestatus[1]}"
echo '$ mutation: one wrong pre-registered reason must fail strict scoring'
rm -rf /tmp/aps-2-mut && cp -r $A/submission/aps-2 /tmp/aps-2-mut
python3 - <<'PY'
import json; p='/tmp/aps-2-mut/submission.json'; s=json.load(open(p))
s['set_id']='aps-2-mut'; s['cases'][2]['expected_aps_reason']='SCOPE_WIDENING'
json.dump(s,open(p,'w'),indent=2)
PY
rm -rf $O/fixtures/aps-2-mut $O/harness-aps-2-mut
python3 -m runner.authority_fixtures assemble --submission /tmp/aps-2-mut/submission.json --out $O/fixtures/aps-2-mut; echo "assemble exit=$?"
python3 -m runner.authority_harness --fixtures $O/fixtures/aps-2-mut --verifier $A/edge/aps --out $O/harness-aps-2-mut --timeout 120 --trust-edge aps 2>&1 | grep -i 'Result\|reasons as expected\|af-3' | head -5; echo "harness exit=${pipestatus[1]}"
echo DONE
