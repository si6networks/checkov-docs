# CKV_GITHUB_7: Ensure GitHub repository webhooks are using HTTPS
## Severity
**HIGH** (score: 7.0/10)

Plaintext HTTP webhook delivery for a repository exposes payloads and shared secrets to network interception, enabling spoofing or tampering of events sent to downstream automation.

## Summary
This check enforces that all repository-level GitHub webhooks deliver payloads over HTTPS with SSL verification enabled, rather than plaintext HTTP or unverified TLS.

## Applicability
Applies to GitHub organization/repository configuration (`github_configuration` IaC type, entity `*`), evaluated against the repository webhooks document (files matching `repository_webhooks`), where each webhook entry has a `config` object with `url` and `insecure_ssl` fields.

## Why it matters
Repository webhooks often relay commit, push, and pull-request event data — sometimes including diffs or metadata about code changes — to third-party integrations (CI systems, chat notifications, deployment triggers). If the destination endpoint uses plain HTTP, this data, along with the webhook's shared secret used for HMAC signature verification, is transmitted unencrypted and can be intercepted or tampered with by anyone on the network path. An attacker who intercepts the secret can forge convincing fake webhook payloads to the receiving system (e.g., triggering a fraudulent deployment). Disabling SSL certificate verification (`insecure_ssl`) similarly exposes the connection to endpoint impersonation via a man-in-the-middle attack, even if the transport is nominally TLS.

## How Checkov evaluates this
For each webhook entry's `config`, the check fails if `url` starts with `http://`. It also fails if `insecure_ssl` is not `'0'` (i.e., SSL certificate verification has been disabled for that webhook). If neither condition triggers for any configured webhook, and the configuration matches the repository webhooks schema, the check passes; otherwise (schema mismatch) the result is UNKNOWN. Note this repository-level check does not have the `secret == '********'` exception that the organization-level webhook check (CKV_GITHUB_6) has — any `insecure_ssl != '0'` fails outright.

## Non-compliant example
```json
[
  {
    "id": 67890,
    "config": {
      "url": "http://ci.example.com/webhook",
      "insecure_ssl": "1"
    }
  }
]
```

## Remediated example
```json
[
  {
    "id": 67890,
    "config": {
      "url": "https://ci.example.com/webhook",
      "insecure_ssl": "0"
    }
  }
]
```

## Remediation steps
1. Update the repository webhook's payload URL to use `https://` (Settings > Webhooks in the repository).
2. Ensure "SSL verification" is enabled (not disabled) for the webhook.
3. If the receiving endpoint currently lacks a valid TLS certificate, obtain one (e.g., via Let's Encrypt) rather than disabling verification.
4. Rotate the webhook secret if there's any chance it was transmitted or logged insecurely in the past.
5. Periodically audit repository webhooks, since they're often created ad hoc by individual contributors and can be forgotten.
6. Re-run the Checkov GitHub scan to confirm the webhook configuration passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/webhooks_https_repos.py)
- [GitHub Docs: Securing your webhooks](https://docs.github.com/en/webhooks/using-webhooks/securing-your-webhooks)
