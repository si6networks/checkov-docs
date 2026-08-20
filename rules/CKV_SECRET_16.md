# CKV_SECRET_16: Square OAuth Secret

## Severity
**LOW** (score: 2.0/10)

A leaked Square OAuth secret or access token exposes payment-processing APIs, customer PII, and merchant financial data, carrying direct fraud and PCI-scope impact.

## Summary
This check scans file contents for hardcoded Square OAuth application secrets (and related Square API access tokens), flagging static payment-platform credentials committed directly into source or config files.

## Applicability
- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (application config, YAML/JSON, `.env` files, scripts, CI pipeline definitions, etc.), not limited to a single IaC resource type.
- **Entities**: the matched credential string within a file; findings are reported at the file/line level.

## Why it matters
A Square OAuth secret (or access token) authenticates an application to Square's payments API, which handles real financial transactions, customer payment instruments, and merchant account data. A leaked OAuth client secret allows an attacker to complete the OAuth flow as your application, potentially tricking merchants into authorizing a malicious "clone" of your integration, or — if a production access token itself leaks — directly call Square APIs to process refunds, view transaction/customer PII, or exfiltrate payout/banking details tied to merchant accounts. Given the direct financial and PCI-scope implications, credentials in this category typically carry regulatory (PCI-DSS) exposure in addition to the immediate fraud risk.

## How Checkov evaluates this
The secrets scanner matches Square's distinctive credential prefixes and formats — OAuth secrets and access tokens issued by Square carry recognizable prefixes (e.g., `sq0csp-` for OAuth client secrets, `sq0atp-`/`EAAA...` for access tokens) followed by a fixed-length base64/alphanumeric string. A match of this structural pattern in scanned file content is reported as a FAIL at that file/line.

## Non-compliant example
```python
# payments_config.py
SQUARE_OAUTH_CLIENT_SECRET = "sq0csp-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St90Uv"
```

## Remediated example
```python
# payments_config.py
import os
SQUARE_OAUTH_CLIENT_SECRET = os.environ["SQUARE_OAUTH_CLIENT_SECRET"]
```

## Remediation steps
1. Regenerate the exposed OAuth client secret / access token immediately in the Square Developer Dashboard (Applications → OAuth) — assume it is compromised.
2. Remove the hardcoded secret from the file and load it from an environment variable or secrets manager at runtime.
3. Purge the secret from git history if it was ever committed/pushed.
4. Review Square's application activity/audit logs for any unauthorized OAuth authorizations or API calls made during the exposure window.
5. Use Square's sandbox credentials for development/testing environments so a leaked test credential cannot touch production payment data.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
