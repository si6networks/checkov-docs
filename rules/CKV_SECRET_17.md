# CKV_SECRET_17: Stripe Access Key

## Severity
**MEDIUM** (score: 5.0/10)

A leaked Stripe live secret key grants full server-side control over charges, refunds, payouts, and customer payment data, a hardcoded credential with direct, immediate financial-fraud impact.

## Summary
This check scans file contents for hardcoded Stripe API keys (secret or restricted live keys), flagging static payment-processing credentials committed directly into source or config files.

## Applicability
- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (application config, YAML/JSON, `.env` files, scripts, CI pipeline definitions, etc.), not limited to a single IaC resource type.
- **Entities**: the matched credential string within a file; findings are reported at the file/line level.

## Why it matters
A Stripe secret key (`sk_live_...`) authenticates full server-side access to a merchant's Stripe account — the ability to create charges, issue refunds, view customer payment methods and PII, create/modify payouts, and manage connected accounts. Unlike the publishable key (`pk_live_...`), which is safe to expose client-side, the secret key is meant to never leave the server. A leaked live secret key gives an attacker direct financial control: they can charge arbitrary amounts to stored customer cards, redirect payouts, or exfiltrate customer PII/payment metadata — all of which carry PCI-DSS and financial-fraud consequences, and typically require immediate key revocation plus a fraud investigation with Stripe support.

## How Checkov evaluates this
The secrets scanner matches Stripe's distinctive key-prefix format — live secret keys begin with `sk_live_`, restricted keys with `rk_live_`, followed by a long alphanumeric string; test-mode equivalents (`sk_test_`, `rk_test_`) follow the same structural pattern and are typically also flagged since they can still be considered sensitive account-identifying material. A match of this prefix-plus-length pattern in scanned file content is reported as a FAIL at that file/line.

## Non-compliant example
```javascript
// paymentService.js
const stripe = require('stripe')('sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
```

## Remediated example
```javascript
// paymentService.js
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
```

## Remediation steps
1. Roll the exposed key immediately in the Stripe Dashboard (Developers → API keys → Roll key) — Stripe also proactively detects and revokes keys leaked to public repos, but do not wait for that.
2. Remove the hardcoded key from the file and load it from an environment variable or secrets manager at runtime.
3. Purge the secret from git history if it was ever committed/pushed.
4. Review the Stripe Dashboard's logs/events for any unauthorized charges, refunds, or payout changes made during the exposure window, and contact Stripe support if fraud is suspected.
5. Use restricted API keys scoped to only the resources/actions a given service actually needs, rather than the full-access secret key, to limit blast radius on future leaks.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
