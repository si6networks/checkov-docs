# CKV2_DOCKER_12: Ensure that certificate validation isn't disabled for npm via the 'NPM_CONFIG_STRICT_SSL' environment variable

## Severity
**HIGH** (score: 7.5/10)

Setting NPM_CONFIG_STRICT_SSL to false disables TLS certificate validation for npm installs, exposing the build pipeline to man-in-the-middle package substitution and supply-chain compromise.

## Summary
This check verifies that the `NPM_CONFIG_STRICT_SSL` (or lowercase `npm_config_strict_ssl`) environment variable is never set to `false` in a Dockerfile, whether via `ARG`/`ENV` or inline in a `RUN` command.

## Applicability
- **Dockerfile**: `ARG`, `ENV`, and `RUN` instructions.

This is a graph-based check using regex matching, evaluated across three different instruction types (it must find no disabling pattern in any of them).

## Why it matters
npm honors the `NPM_CONFIG_STRICT_SSL` environment variable as an alternative to the `strict-ssl` config setting; setting it to `false` disables TLS certificate validation for all HTTPS registry requests npm makes during that build step. This exposes the build to man-in-the-middle attacks: an attacker positioned on the network path (compromised DNS, rogue Wi-Fi, compromised CI runner network, malicious proxy) could serve a tampered package or metadata response, and npm would accept it without any certificate validation. Because this happens at build time and gets baked into the resulting image/dependency tree, a single MITM'd build can inject malicious code that then ships to every downstream consumer of that image — a classic supply-chain compromise vector.

## How Checkov evaluates this
The check is a JSON graph query, an `or` of two independent regex checks — either being clean is sufficient in isolation, but in practice both are evaluated across the relevant instructions:

- FAIL: an `ARG` or `ENV` instruction's value matches `(NPM_CONFIG_STRICT_SSL|npm_config_strict_ssl)(=|\s+)(false|'false'|"false")`.
- FAIL: a `RUN` instruction's value matches `... (NPM_CONFIG_STRICT_SSL|npm_config_strict_ssl)=(false|'false'|"false") ...` (inline env-var assignment prefixing a command).
- PASS: neither pattern is found anywhere in the Dockerfile's `ARG`/`ENV`/`RUN` instructions.

## Non-compliant example
```dockerfile
FROM node:20

ENV NPM_CONFIG_STRICT_SSL=false
RUN npm install
```

## Remediated example
```dockerfile
FROM node:20

# Removed NPM_CONFIG_STRICT_SSL=false: certificate validation stays enabled
RUN npm install
```

## Remediation steps
1. Remove any `ENV`/`ARG` setting `NPM_CONFIG_STRICT_SSL` (or `npm_config_strict_ssl`) to `false`, and remove any inline `NPM_CONFIG_STRICT_SSL=false npm ...` prefix in `RUN` commands.
2. If the original motivation was a corporate TLS-intercepting proxy with a private CA, install that CA certificate into the image's trust store (e.g., via `update-ca-certificates`) and/or point npm at it with `NODE_EXTRA_CA_CERTS`, rather than disabling validation entirely.
3. If the issue was an expired or misconfigured internal registry certificate, fix the registry's certificate — do not work around it in every consuming Dockerfile.
4. Verify no build args pass `false` through indirectly (e.g., `--build-arg NPM_CONFIG_STRICT_SSL=false`) at build invocation time, since Checkov's static analysis only sees what's declared in the Dockerfile/args used within it.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/EnvNpmConfigStrictSsl.json)
