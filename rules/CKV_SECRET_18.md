# CKV_SECRET_18: Twilio API Key

## Severity
**LOW** (score: 2.0/10)

A leaked Twilio credential can be used to intercept OTP/2FA SMS codes, send phishing messages from a trusted sender, and incur fraudulent usage charges, a hardcoded credential enabling authentication bypass.

## Summary
This check scans file contents for hardcoded Twilio API keys/secrets (and account SID/auth-token pairs), flagging static telephony/messaging-platform credentials committed directly into source or config files.

## Applicability
- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (application config, YAML/JSON, `.env` files, scripts, CI pipeline definitions, etc.), not limited to a single IaC resource type.
- **Entities**: the matched credential string within a file; findings are reported at the file/line level.

## Why it matters
Twilio credentials authenticate programmatic access to send SMS/MMS messages, place and record voice calls, and manage phone numbers on a billed account. A leaked API key or Account SID/Auth Token pair lets an attacker send messages (including phishing/smishing) from your organization's verified sender numbers — abusing your sender reputation and trust — place expensive international calls at your expense, or access call/message logs and recordings that may contain sensitive customer communications and PII (e.g., OTP codes sent for authentication, which an attacker could intercept to defeat SMS-based 2FA for your users). Twilio billing is usage-based, so a leaked credential can also result in a large, unexpected bill from abuse before it's detected.

## How Checkov evaluates this
The secrets scanner matches Twilio's distinctive credential formats — API Key SIDs begin with `SK` followed by 32 hexadecimal characters, Account SIDs begin with `AC` followed by 32 hex characters, and Auth Tokens/API secrets are 32-character hexadecimal strings typically found alongside them in config (`TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`). A match of these structural patterns in scanned file content is reported as a FAIL at that file/line.

## Non-compliant example
```python
# sms_notifier.py
from twilio.rest import Client
account_sid = "AC1234567890abcdef1234567890abcdef"
auth_token  = "1234567890abcdef1234567890abcdef"
client = Client(account_sid, auth_token)
```

## Remediated example
```python
# sms_notifier.py
import os
from twilio.rest import Client
account_sid = os.environ["TWILIO_ACCOUNT_SID"]
auth_token  = os.environ["TWILIO_AUTH_TOKEN"]
client = Client(account_sid, auth_token)
```

## Remediation steps
1. Revoke/regenerate the exposed Auth Token or API Key immediately in the Twilio Console (Account → API keys & tokens) — assume it is compromised.
2. Remove the hardcoded credential from the file and load it from an environment variable or secrets manager at runtime.
3. Purge the secret from git history if it was ever committed/pushed.
4. Prefer scoped API Keys over the primary Account Auth Token where possible, since API Keys can be individually revoked without invalidating the entire account's primary token.
5. Review the Twilio Console's usage/billing logs for anomalous message/call volume during the exposure window, and set up usage-trigger alerts to catch abuse faster in the future.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
