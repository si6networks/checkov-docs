# CKV_SECRET_12: NPM tokens

## Severity
**LOW** (score: 2.0/10)

A leaked npm publish token enables a supply-chain attack: an attacker can push a malicious package version that is automatically pulled by every downstream consumer's install/CI pipeline.

## Summary
This check scans file contents for hardcoded npm registry authentication tokens, flagging static publish/install credentials committed directly into source, `.npmrc`, or CI config files.

## Applicability
- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (`.npmrc`, CI pipeline YAML, Dockerfiles, shell scripts, application config, etc.), not limited to a single IaC resource type.
- **Entities**: the matched credential string within a file; findings are reported at the file/line level.

## Why it matters
An npm access token grants whatever permissions were assigned when it was created — commonly the ability to publish new versions of packages the associated account/org owns, and sometimes broader read access to private packages. A leaked publish-capable npm token is a supply-chain attack vector: an attacker can push a malicious version of a package your organization owns (or a private internal package many other services depend on), which is then automatically pulled by every consumer's `npm install`/CI pipeline — a blast radius far larger than the original repository. Even a read-only token exposes private package source code. Because npm tokens are frequently embedded in `.npmrc` files for CI publishing workflows, they are a recurring category of accidental commits.

## How Checkov evaluates this
The secrets scanner matches the structural format of npm access tokens — modern tokens use a distinctive `npm_` prefix followed by a fixed-length alphanumeric string; legacy tokens are UUID-formatted strings typically found in `.npmrc` as `//registry.npmjs.org/:_authToken=<token>`. The detector looks for either the `npm_`-prefixed pattern or the `_authToken=` assignment pattern in scanned file content; a match is reported as a FAIL at that file/line.

## Non-compliant example
```ini
# .npmrc
//registry.npmjs.org/:_authToken=npm_1A2b3C4d5E6f7G8h9I0jK1l2M3n4O5p6Q7r8
```

## Remediated example
```ini
# .npmrc
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
```

## Remediation steps
1. Revoke the exposed token immediately from npmjs.com (Account Settings → Access Tokens) — assume it is compromised.
2. Remove the literal token from `.npmrc`/scripts and reference an environment variable (`${NPM_TOKEN}`) populated by your CI/CD secrets store instead.
3. Use "Automation" or "Publish"-scoped tokens rather than tokens with full account access, and prefer granular per-package/per-org tokens where npm supports them.
4. Purge the secret from git history if it was ever committed/pushed.
5. Audit the package registry's publish history for any versions published after the leak that you did not authorize.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
