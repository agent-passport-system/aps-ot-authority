# Verifier image for the autonomous-ot-control authority_fixture harness.
# The executable lives in /opt/aps because the harness mounts the edge directory over /edge.
FROM node:24-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c
COPY edge/aps/verify.mjs edge/aps/trust.json edge/aps/LICENSE /opt/aps/
USER 65534:65534
