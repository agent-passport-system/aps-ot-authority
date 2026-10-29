#!/bin/zsh
export PATH="/opt/homebrew/bin:$HOME/.local/bin:$PATH"
A=~/work/aps-ot-authority; T=~/work/ot-pr38; O=$A/runs/day255
cd $A
echo '$ npx --yes esbuild@0.25.10 verifier/verify.mjs --bundle --platform=node --format=esm --target=node20 --define:__SDK_VERSION__="8.0.1" --outfile=edge/aps/verify.mjs'
npx --yes esbuild@0.25.10 verifier/verify.mjs --bundle --platform=node --format=esm --target=node20 --define:__SDK_VERSION__='"8.0.1"' --outfile=edge/aps/verify.mjs; echo "esbuild exit=$?"
SHA=$(shasum -a 256 edge/aps/verify.mjs | cut -d' ' -f1); echo "bundle sha256 $SHA"
python3 - "$SHA" <<'PY'
import json,sys
p='edge/aps/edge.json'; e=json.load(open(p)); e['bundle']['sha256']=sys.argv[1]
json.dump(e,open(p,'w'),indent=2); open(p,'a').write('\n'); print('edge.json sha updated')
PY
cd $T
rm -rf $O/harness-aps-2
echo '$ python3 -m runner.authority_harness --fixtures runs/day255/fixtures/aps-2 --verifier edge/aps --out runs/day255/harness-aps-2 --timeout 120 --trust-edge aps'
python3 -m runner.authority_harness --fixtures $O/fixtures/aps-2 --verifier $A/edge/aps --out $O/harness-aps-2 --timeout 120 --trust-edge aps; echo "harness exit=$?"
echo DONE
