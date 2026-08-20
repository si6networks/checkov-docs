# CKV_SECRET_1: Artifactory Credentials

## Severity
**MEDIUM** (score: 5.0/10)

A leaked Artifactory credential grants read/write access to the artifact repository, enabling supply-chain attacks via poisoned build artifacts or exfiltration of proprietary binaries.

## Summary
This check scans plaintext files (any file type Checkov's secrets scanner processes) for hardcoded JFrog Artifactory credentials — API keys or access tokens — committed directly into source, config, or script files.

## Applicability
**Checkov framework(s):** `secrets`

- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, which runs over all scanned files regardless of format (Terraform, YAML, scripts, config files, `.env` files, Dockerfiles, etc.), not a single resource type.
- **Entities**: any file content matching the credential pattern; there is no "resource type" in the IaC-graph sense — the finding is reported against the file and line where the string appears.

## Why it matters
Artifactory credentials grant read/write access to your organization's binary artifact repository — build outputs, container images, private package feeds, and release artifacts. A leaked Artifactory API key or access token in a git-tracked file (especially one pushed to a public or broadly-shared repository) allows an attacker to pull proprietary build artifacts, poison the artifact stream by uploading malicious packages/images that downstream CI/CD or production systems later consume (a supply-chain attack), or exfiltrate intellectual property. Because Artifactory tokens are frequently long-lived and scoped broadly (sometimes admin-level), and because git history retains the secret even after later removal from HEAD, a single accidental commit can require a full credential rotation and history-scrub.

## How Checkov evaluates this
Checkov's secrets framework (built on regex/entropy detectors similar to Yelp's `detect-secrets`) scans file contents line-by-line for patterns characteristic of Artifactory credentials — this includes JFrog's API key format and access-token format (long alphanumeric tokens, often prefixed or found alongside keys like `artifactory_api_key`, `ARTIFACTORY_TOKEN`, or embedded in `.netrc`/CI config). A match on the pattern (and, where applicable, minimum Shannon entropy to reduce false positives on non-secret-looking strings) triggers a FAIL at that file/line. There is no PASS condition based on attribute configuration as with resource-graph checks — the check simply reports every matched credential-shaped string; the only way to "pass" is for no such string to be present in the scanned content.

## Non-compliant example
```yaml
# .circleci/config.yml
environment:
  ARTIFACTORY_URL: "https://mycompany.jfrog.io/artifactory"
  ARTIFACTORY_API_KEY: "AKCp8jQdR3Tn9zP1kLmN6vQxYz2Wc7Hs4Ef8Gt5Bj3Rq9Xw6Yv1U"
```

## Remediated example
```yaml
# .circleci/config.yml
environment:
  ARTIFACTORY_URL: "https://mycompany.jfrog.io/artifactory"
  ARTIFACTORY_API_KEY: "${ARTIFACTORY_API_KEY}"  # injected from CircleCI project env var / secrets store
```

## Remediation steps
1. Immediately revoke/rotate the exposed Artifactory API key or access token in the JFrog platform admin console — assume it is compromised the moment it is committed.
2. Remove the literal credential from the file and replace with a reference to a secrets manager, CI/CD masked environment variable, or Vault-style dynamic secret.
3. Purge the secret from git history (e.g., `git filter-repo` or BFG Repo-Cleaner) if it was ever pushed, not just the latest commit — Checkov flags working-tree content, but the exposure risk lives in history too.
4. Add a `.checkov.yaml`/pre-commit hook running the secrets scanner locally so future commits are caught before push.
5. Prefer short-lived, scoped tokens (JFrog supports scoped access tokens) over long-lived admin-level API keys to limit blast radius if a future leak occurs.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
