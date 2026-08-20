# CKV2_DOCKER_13: Ensure that certificate validation isn't disabled for npm or yarn by setting the option strict-ssl to false

## Severity
**HIGH** (score: 7.5/10)

Setting npm/yarn strict-ssl to false removes certificate validation on package downloads, letting an attacker positioned on the network inject malicious packages during the build.

## Summary
This check verifies that no `RUN` instruction in a Dockerfile disables TLS certificate validation for `npm` or `yarn` by running `npm config set strict-ssl false` (or the yarn equivalent).

## Applicability
**Checkov framework(s):** `dockerfile`

- **Dockerfile**: any `RUN` instruction.

This is a graph-based check using regex matching against the `RUN` instruction's command text.

## Why it matters
Both `npm` and `yarn` support a `strict-ssl` configuration option that, when set to `false`, disables TLS certificate validation for all HTTPS requests made to package registries. Unlike the environment-variable form (see CKV2_DOCKER_12), this check specifically targets the explicit `npm config set strict-ssl false` / `yarn config set strict-ssl false` CLI invocation. The security impact is identical: any HTTPS connection to the registry (or a registry mirror/proxy) can be intercepted and tampered with by a network-positioned attacker without detection, because the client will accept any certificate — self-signed, expired, or issued for the wrong domain — as valid. Since package installs run arbitrary install/postinstall scripts, a single tampered package delivered this way is equivalent to arbitrary code execution during the image build, with the result baked permanently into the resulting image layers.

## How Checkov evaluates this
The check is a JSON graph query using a `not_regex_match` operator against the `RUN` instruction's `value`:

- FAIL: the command text matches `(npm|yarn) (config )?set strict-ssl(=| )(false|"false"|'false')` (allowing for optional quoting of `strict-ssl` and the `config`/`c` subcommand form, and either `=` or whitespace before the value).
- PASS: no such pattern appears in the `RUN` instruction.

## Non-compliant example
```dockerfile
FROM node:20

RUN npm config set strict-ssl false && npm install
```

## Remediated example
```dockerfile
FROM node:20

# Removed strict-ssl override: certificate validation stays enabled
RUN npm install
```

## Remediation steps
1. Remove `npm config set strict-ssl false` / `yarn config set strict-ssl false` from all `RUN` instructions.
2. If the goal was to work around a corporate TLS-intercepting proxy, install the proxy's CA certificate into the image and configure `npm config set cafile <path>` (or `NODE_EXTRA_CA_CERTS`) instead of disabling validation.
3. If the goal was to work around an expired/misconfigured internal registry certificate, fix the registry certificate rather than disabling client-side verification in every Dockerfile that consumes it.
4. Re-check this Dockerfile (`src/cloud/frontend/self-serve-video/Dockerfile`) specifically, since it is one of the confirmed active findings in this repository — remove the offending `RUN` line and rebuild/retest the image.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/dockerfile/checks/graph_checks/RunNpmConfigSetStrictSsl.json)
