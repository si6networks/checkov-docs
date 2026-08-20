# CKV_SECRET_4: Basic Auth Credentials

## Severity
**MEDIUM** (score: 5.0/10)

Embedded Basic Auth credentials in a URL are a plaintext username/password pair that, once exposed (including via logs), grant direct authenticated access to the target system and are frequently reused elsewhere, enabling credential-stuffing.

## Summary
This check scans file contents for URLs or connection strings containing embedded HTTP Basic Authentication credentials in the form `scheme://user:password@host`, flagging plaintext usernames/passwords committed directly into source or config.

## Applicability
- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (Terraform, YAML/JSON config, Dockerfiles, CI pipeline definitions, `.env` files, application config, scripts, etc.), not limited to a single IaC resource type.
- **Entities**: the matched credential-bearing URL string within a file; findings are reported at the file/line level.

## Why it matters
Embedding `user:password` directly in a URL is one of the oldest and most common accidental-leak patterns — it appears in database connection strings, internal API endpoints, git remotes, webhook URLs, and package registry configs. Because the credential is inline with the URL rather than a separate secret, it is easy to overlook during code review (the string "looks like" a normal endpoint reference) and frequently ends up duplicated across logs, error messages, and crash reports whenever the URL is printed or an HTTP client logs its request line — meaning the exposure isn't limited to the source file itself. If the target service is reachable from the internet (a database, an internal API, an artifact registry), the leaked credential provides direct authenticated access, and unlike a scoped API token, Basic Auth credentials are frequently a full username/password pair reused elsewhere, expanding the impact to credential-stuffing attacks against other systems.

## How Checkov evaluates this
The secrets scanner pattern-matches URLs/connection-string-like tokens where the authority component contains a `user:password@` segment before the host — i.e., strings matching `<scheme>://<user>:<password>@<host>...`. Any scanned file content matching this structural pattern is reported as a FAIL at that file/line; the detector does not need to know the target protocol (it fires for `http(s)://`, `ftp://`, `postgres://`, `mongodb://`, etc. equally, since the vulnerable pattern is structural, not protocol-specific).

## Non-compliant example
```yaml
# docker-compose.yml
services:
  worker:
    environment:
      DATABASE_URL: "postgres://admin:SuperSecret123@db.internal.example.com:5432/appdb"
```

## Remediated example
```yaml
# docker-compose.yml
services:
  worker:
    environment:
      DATABASE_URL: "${DATABASE_URL}"  # injected at deploy time from a secrets manager
```

## Remediation steps
1. Rotate the exposed credential at the target system (database, API, registry) immediately — assume it is compromised.
2. Remove the inline `user:password@` segment from the URL and pass credentials via a separate secret reference (environment variable injected from a vault/secrets manager, Kubernetes Secret, cloud Secrets Manager, etc.) rather than embedding them in the connection string literal.
3. Where the client library supports it, use a dedicated auth parameter/config field instead of a combined URL (e.g., separate `username`/`password` driver options) so the credential never has to be string-concatenated into a URL that might get logged.
4. Audit logging configuration to ensure connection strings/URLs are not printed verbatim in application or proxy logs going forward.
5. Purge the secret from git history if it was ever committed/pushed.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
