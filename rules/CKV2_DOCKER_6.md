# CKV2_DOCKER_6: Ensure that certificate validation isn't disabled with the NODE_TLS_REJECT_UNAUTHORIZED environment variable
## Severity
**HIGH** (score: 7.5/10)

NODE_TLS_REJECT_UNAUTHORIZED=0 globally disables TLS certificate verification for the Node.js runtime, and since it is set as an image environment variable it commonly carries through to the running application, exposing all outbound HTTPS traffic to MITM interception.

## Summary
This check fails a Dockerfile if it sets `NODE_TLS_REJECT_UNAUTHORIZED` to `0` (via `ARG`, `ENV`, or inline in a `RUN` command), which globally disables TLS certificate verification for the Node.js runtime and for `npm`/`yarn`/`node` HTTPS clients.

## Applicability
Applies to `Dockerfile` builds. Implemented as a Checkov graph-based JSON policy checking `ARG`, `ENV`, and `RUN` instructions.

## Why it matters
`NODE_TLS_REJECT_UNAUTHORIZED=0` is a well-known, explicitly-warned-against Node.js setting that disables all TLS certificate chain/hostname validation for the process (Node itself prints a security warning when it's used). It affects `npm install`/`yarn install` package downloads, any `https`/`tls` module usage, and every HTTP client library built on top of them. Because it's set as an environment variable rather than a one-off flag, it silently weakens every subsequent network call made by Node.js in that image or container — including production application code if the variable is baked into `ENV` and carried into the runtime stage — leaving the service permanently open to MITM attacks on outbound HTTPS traffic (credential theft, response tampering, malicious package injection during `npm install`).

## How Checkov evaluates this
An `or` of two `attribute` conditions; FAIL if either matches:
1. Any `ARG`/`ENV` `value` matches `(.*\s+)?(NODE_TLS_REJECT_UNAUTHORIZED(=|\s+)((0)|('0')|("0")))`.*` — the variable set to `0` in any quoting style.
2. Any `RUN` `value` matches `(.*[\s;&|]+)?(NODE_TLS_REJECT_UNAUTHORIZED=((0)|('0')|("0"))) .*` — an inline `NODE_TLS_REJECT_UNAUTHORIZED=0` prefix within a shell command.

PASS otherwise.

## Non-compliant example
```dockerfile
FROM node:20-alpine
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
RUN npm ci --omit=dev
```

## Remediated example
```dockerfile
FROM node:20-alpine
# NODE_TLS_REJECT_UNAUTHORIZED left at its secure default (verification enabled)
RUN npm ci --omit=dev
```

## Remediation steps
1. Remove `NODE_TLS_REJECT_UNAUTHORIZED=0` from all `ENV`, `ARG`, and inline `RUN` usages.
2. Fix the underlying cause instead: install a proper CA cert for internal/self-signed registries via `NODE_EXTRA_CA_CERTS=/path/to/ca.pem` (a supported, scoped alternative) or configure the trust store at the OS level.
3. For npm specifically, prefer `npm config set cafile <path>` or `NODE_EXTRA_CA_CERTS` over disabling verification entirely.
4. Check any multi-stage builds and base images to ensure this variable isn't inherited into the final runtime `ENV`.
5. Re-scan with Checkov to confirm.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/EnvNodeTlsRejectUnauthorized.json
