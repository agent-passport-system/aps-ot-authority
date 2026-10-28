# aps: APS delegation verifier for the authority_fixture harness

Single file, no install step. `verify.mjs` is `../../verifier/verify.mjs` bundled with
agent-passport-system 8.0.1 by esbuild 0.25.10 (`--bundle --platform=node --format=esm
--target=node20`). Source, lockfile and self-test stay in `verifier/`. Rebuild:

    npx --yes esbuild@0.25.10 verifier/verify.mjs --bundle --platform=node --format=esm \
      --target=node20 --define:__SDK_VERSION__='"8.0.1"' --outfile=edge/aps/verify.mjs

`edge.json` pins the container image `node:24-slim` by digest and records the bundle's
sha256. `trust.json` holds the test-only root key. The verifier decides only the delegation
side of the contract and never reads the value, the unit or the work order.

Run from the testbed checkout:

    python -m runner.authority_harness --fixtures <sealed set> --verifier <this dir> --out <out> --trust-edge aps

Without `--trust-edge aps` the harness runs the edge in its Docker sandbox using the pinned image.
