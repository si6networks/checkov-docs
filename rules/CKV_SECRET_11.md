# CKV_SECRET_11: Mailchimp Access Key

## Severity
**LOW** (score: 2.0/10)

A leaked Mailchimp API key exposes the full subscriber PII database and lets an attacker send phishing campaigns from a trusted sending domain, a hardcoded-credential exposure with direct data-breach and brand-abuse impact.

## Summary
This check scans file contents for hardcoded Mailchimp API keys, flagging static marketing-platform credentials committed directly into source or config files.

## Applicability
- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (application config, YAML/JSON, `.env` files, scripts, CI pipeline definitions, etc.), not limited to a single IaC resource type.
- **Entities**: the matched credential string within a file; findings are reported at the file/line level.

## Why it matters
A Mailchimp API key grants full programmatic access to the account's audiences (mailing lists), campaign management, and — critically — the personal data of every subscriber (names, email addresses, and any custom merge fields collected, which can include phone numbers, addresses, or purchase history). A leaked key allows an attacker to exfiltrate the entire subscriber database (a GDPR/CCPA-relevant personal-data breach), send phishing campaigns "from" your legitimate sending domain and reputation (damaging deliverability and brand trust), or delete audiences and campaign history outright. Because Mailchimp keys are long-lived and account-wide (not scoped to a single list or read-only), the blast radius of a leak is the entire marketing/CRM data set tied to that account.

## How Checkov evaluates this
The secrets scanner matches the structural format of Mailchimp API keys — a 32-character hexadecimal string followed by a datacenter suffix (e.g., `-us14`, `-us21`) that identifies the Mailchimp server shard the account is hosted on. This suffix is a distinctive marker that, combined with the fixed-length hex prefix, makes the pattern reliably identifiable in scanned file content; a match is reported as a FAIL at that file/line.

## Non-compliant example
```python
# newsletter_sync.py
MAILCHIMP_API_KEY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6-us14"
```

## Remediated example
```python
# newsletter_sync.py
import os
MAILCHIMP_API_KEY = os.environ["MAILCHIMP_API_KEY"]
```

## Remediation steps
1. Revoke/regenerate the exposed API key in the Mailchimp account settings (Account → Extras → API keys) — assume it is compromised.
2. Remove the hardcoded key from the file and load it from an environment variable or secrets manager at runtime.
3. Purge the secret from git history if it was ever committed/pushed.
4. Where possible, create a separate, narrowly-scoped API key per integration rather than reusing one account-wide key across multiple services, to limit blast radius on a future leak.
5. Review Mailchimp's account activity log after rotation for any unauthorized API calls made with the old key.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
