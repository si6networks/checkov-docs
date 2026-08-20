# CKV_SECRET_14: Slack Token

## Severity
**MEDIUM** (score: 5.0/10)

A leaked Slack token can exfiltrate private message/file history and be used to post convincing internal phishing content, a hardcoded credential with direct data-exposure and social-engineering impact.

## Summary
This check scans file contents for hardcoded Slack tokens (bot, user, workspace, or webhook tokens), flagging static Slack API credentials committed directly into source, config, or CI pipeline files.

## Applicability
- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (YAML/JSON config, CI pipeline definitions, scripts, application config, etc.), not limited to a single IaC resource type.
- **Entities**: the matched token string within a file; findings are reported at the file/line level.

## Why it matters
Slack tokens authenticate as a bot, user, or app within a workspace and can grant access to read/post messages, list users, download files shared in channels, and — depending on scopes — access private channels and direct messages. A leaked Slack token in a repeatedly-run integration test or data-offload pipeline (as seen in this repo's examples) is especially risky because such tokens tend to be provisioned with broad scopes for automation convenience and are reused across dev/test/prod environments. An attacker with a leaked token can exfiltrate the full message history and files the token has access to, impersonate the bot/user to post disinformation or phishing links internally (which employees are primed to trust since it appears to come from a legitimate internal integration), and enumerate workspace membership for social-engineering targeting.

## How Checkov evaluates this
The secrets scanner matches Slack's distinctive token-prefix formats — tokens beginning with `xoxb-` (bot), `xoxp-` (user/legacy), `xoxa-`/`xoxr-` (app/refresh), or `xoxs-` (workspace), followed by the characteristic dash-delimited numeric/alphanumeric segments Slack issues. It also matches Slack incoming-webhook URLs (`hooks.slack.com/services/...`) which, while not a "token" in the OAuth sense, function as an unauthenticated bearer credential for posting to a channel. Any match of these structural patterns in scanned file content is reported as a FAIL at that file/line.

## Non-compliant example
```yaml
# offload_data.yaml
notifications:
  slack:
    webhook_url: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    bot_token: "xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
```

## Remediated example
```yaml
# offload_data.yaml
notifications:
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    bot_token: "${SLACK_BOT_TOKEN}"
```

## Remediation steps
1. Revoke/regenerate the exposed token(s) immediately in the Slack app configuration (api.slack.com/apps → your app → OAuth & Permissions / Install App) — assume compromise for all three affected files.
2. Remove the literal tokens/webhook URLs from all three YAML files and replace with references to environment variables populated from a secrets manager or CI/CD masked secrets.
3. Regenerate the incoming webhook URL as well — webhook URLs are bearer credentials and cannot be "scoped down," only revoked and reissued.
4. Since this appears in both a production service path and integration test fixtures, audit whether test fixtures were using a real workspace token — test/dev credentials should use a dedicated sandbox Slack workspace, never a token with access to production channels.
5. Purge the secrets from git history if they were ever committed/pushed, given they appear in multiple files/commits.
6. Add a pre-commit secrets-scan hook to catch this class of leak before it reaches CI in the future.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
