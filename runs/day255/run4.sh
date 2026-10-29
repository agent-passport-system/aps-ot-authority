#!/bin/zsh
export PATH="/opt/homebrew/bin:$HOME/.local/bin:$PATH"
A=~/work/aps-ot-authority; T=~/work/ot-pr38; O=$A/runs/day255
cd $A
echo "$ node mint/mint.mjs   (at $(git rev-parse HEAD))"
node mint/mint.mjs; echo "mint exit=$?"
echo '$ node verifier/selftest.mjs'
node verifier/selftest.mjs | tail -1; echo "selftest exit=${pipestatus[1]}"
cd $T; echo "testbed $(git rev-parse HEAD) (PR #38 head)"
rm -rf $O/fixtures $O/harness-aps-2 $O/harness-aps-1-strict $O/harness-aps-1-legacy
echo '$ python3 -m runner.authority_fixtures assemble --submission submission/aps-2/submission.json --out runs/day255/fixtures/aps-2'
python3 -m runner.authority_fixtures assemble --submission $A/submission/aps-2/submission.json --out $O/fixtures/aps-2; echo "assemble exit=$?"
python3 -m runner.authority_fixtures check $O/fixtures/aps-2; echo "check exit=$?"
echo '$ python3 -m runner.authority_harness --fixtures runs/day255/fixtures/aps-2 --verifier edge/aps --out runs/day255/harness-aps-2 --timeout 120 --trust-edge aps'
python3 -m runner.authority_harness --fixtures $O/fixtures/aps-2 --verifier $A/edge/aps --out $O/harness-aps-2 --timeout 120 --trust-edge aps > $O/harness-aps-2.md 2>&1; echo "harness exit=$?"
grep -E 'Result|as expected' $O/harness-aps-2.md
echo '$ pytest -q tests/unit/test_authority_harness.py tests/unit/test_work_order.py  (testbed own tests at PR head, on this Mac)'
python3 -m pytest -q tests/unit/test_authority_harness.py tests/unit/test_work_order.py 2>&1 | tail -2
echo DONE
