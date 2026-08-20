# CKV_GITHUB_14: Ensure all checks have passed before the merge of new code
## Severity
**MEDIUM** (score: 5.5/10)

Not requiring status checks to pass before merge allows code that fails security scans, tests, or linting to reach the default branch and downstream build/release pipelines.

## Summary
This check fails when a branch protection rule does not require status checks to pass before merging (`required_status_checks`), meaning code can be merged into a protected branch even if CI, tests, linting, or security scans have failed or never run.

## Applicability
- **Framework:** GitHub repository configuration (`github_configuration` — branch protection settings)
- **Entities:** `*`, evaluated against the `required_status_checks` field

## Why it matters
CI pipelines commonly run unit tests, static analysis (including tools like Checkov itself), dependency/vulnerability scanning, and build verification. If a branch protection rule doesn't require these checks to pass before merge, a contributor can merge a PR that fails tests, introduces a known vulnerability, or breaks the build — either accidentally, or deliberately by a malicious actor who wants to slip a change past automated defenses while they're red. This directly undermines every other automated security gate in the pipeline (SAST/DAST scanning, secret scanning, dependency auditing): those tools only provide protection if their pass/fail result is actually enforced as a merge gate, not merely advisory.

## How Checkov evaluates this
This is a `BranchSecurity`-based check (`GithubBranchRequireStatusChecks`) evaluating the `required_status_checks` key. If this configuration object is present/truthy (status checks are required), the check **PASSES**; if absent/empty, it **FAILS**.

## Non-compliant example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1
  }
}
```
No `required_status_checks` block — CI results are shown on the PR but do not block merging.

## Remediated example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1
  },
  "required_status_checks": {
    "strict": true,
    "contexts": ["ci/build", "ci/unit-tests", "checkov-scan"]
  }
}
```

## Remediation steps
1. Go to **Settings → Branches**, edit the branch protection rule, and enable **"Require status checks to pass before merging"**.
2. Select the specific required checks (build, tests, security scans) that must succeed — an empty/generic requirement with no contexts selected provides little protection.
3. Enable **"Require branches to be up to date before merging"** (the `strict: true` option) so checks are re-evaluated against the latest base branch state, preventing a stale "passing" result from being merged after the base branch changed underneath it.
4. If using Terraform's `github_branch_protection` resource, set `required_status_checks { strict = true; contexts = [...] }`.
5. Periodically review the list of required contexts as your CI pipeline evolves — a renamed or removed CI job can otherwise silently stop being enforced.
6. Re-run Checkov to confirm `required_status_checks` is configured.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/require_status_checks_pr.py
- GitHub documentation on required status checks: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging
