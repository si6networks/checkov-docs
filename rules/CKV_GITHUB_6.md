# CKV_GITHUB_6: Ensure GitHub organization webhooks are using HTTPS
## Severity
**HIGH** (score: 7.0/10)

Plaintext HTTP webhook delivery at the organization level exposes payloads and shared secrets to network interception, enabling spoofing or tampering of events sent to downstream automation.

## Summary
This check enforces that all organization-level GitHub webhooks deliver payloads over HTTPS and, when SSL verification is disabled, that the webhook secret is properly redacted rather than exposed.

## Applicability
**Checkov framework(s):** `github_configuration`

Applies to GitHub organization configuration (`github_configuration` IaC type, entity `*`), evaluated against the organization webhooks document (files matching `org_webhooks`), where each webhook entry has a `config` object with `url`, `insecure_ssl`, and `secret` fields.

## Why it matters
Organization webhooks deliver event payloads — which can include repository metadata, commit details, and sometimes sensitive contextual data — to an external endpoint chosen by whoever configured the webhook. If that endpoint is `http://` rather than `https://`, the payload (and the webhook secret used to authenticate it, if sent insecurely) travels in plaintext across the network, making it trivially interceptable by anyone positioned on the network path (a classic man-in-the-middle scenario). An attacker who intercepts webhook traffic can read event details or, worse, capture the shared secret and later forge fake webhook deliveries that the receiving service will trust. Disabling SSL verification (`insecure_ssl`) compounds this by removing protection against endpoint impersonation, unless the secret itself is safely redacted.

## How Checkov evaluates this
For each webhook entry's `config`, the check fails if `url` starts with `http://` (the `HTTP` prefix constant). It also fails if `insecure_ssl` is not `'0'` (i.e., SSL verification is disabled) *and* the `secret` field is not the redacted placeholder `'********'` — meaning an actual secret value is present alongside disabled SSL verification, a doubly risky combination. If neither condition triggers across any webhook, and the configuration matches the organization webhooks schema, the check passes. If the configuration doesn't match the expected schema/file, the result is UNKNOWN.

## Non-compliant example
```json
[
  {
    "id": 12345,
    "config": {
      "url": "http://webhook.example.com/github-events",
      "insecure_ssl": "1",
      "secret": "supersecretvalue"
    }
  }
]
```

## Remediated example
```json
[
  {
    "id": 12345,
    "config": {
      "url": "https://webhook.example.com/github-events",
      "insecure_ssl": "0",
      "secret": "********"
    }
  }
]
```

## Remediation steps
1. Update every organization webhook's payload URL to use `https://`.
2. Ensure "SSL verification" is enabled for each webhook (do not disable certificate validation) so the `insecure_ssl` setting is `0`.
3. If a legacy endpoint genuinely cannot support valid TLS, at minimum ensure the secret is stored/rotated properly rather than left exposed, and prioritize migrating the endpoint to HTTPS.
4. Rotate the webhook secret if you suspect it was ever transmitted or stored insecurely.
5. Audit organization webhooks periodically (Settings > Webhooks) since these are easy to set up ad hoc and forget about.
6. Re-run the Checkov GitHub scan to confirm the webhook configuration passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/webhooks_https_orgs.py)
- [GitHub Docs: Securing your webhooks](https://docs.github.com/en/webhooks/using-webhooks/securing-your-webhooks)
