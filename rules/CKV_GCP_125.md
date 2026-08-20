# CKV_GCP_125: Ensure GCP GitHub Actions OIDC trust policy is configured securely

## Severity
**HIGH** (score: 7.5/10)

A weak or missing attribute_condition on a GitHub Actions OIDC trust policy lets any workflow (including from unrelated or forked repositories) mint credentials and fully impersonate the trusted GCP service account, a documented real-world workload-identity-federation takeover pattern.

## Summary
This check performs a deep validation of `google_iam_workload_identity_pool_provider` resources that trust GitHub Actions' OIDC issuer, failing if the `attribute_condition` does not properly restrict which GitHub repository (and claim) can assume the mapped GCP identity.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_iam_workload_identity_pool_provider`
- **Check type:** resource

## Why it matters
This check goes further than the generic "some condition exists" check (CKV_GCP_118) to catch specific, well-known ways an `attribute_condition` can look protective while still being exploitable:
- **No condition at all**: any GitHub Actions run from any repo can authenticate.
- **Wildcard claim values** (e.g. `assertion.sub == '*'` or `repo:*`): defeats the purpose of the condition entirely.
- **Abusable claims**: some claims returned by GitHub's OIDC tokens are attacker-influenceable — for example, values that can be set by *anyone* who can open a workflow run against your repo (e.g. via a pull request from a fork), such as `job_workflow_ref` in certain contexts, `actor`, or similar identity-adjacent claims that aren't as strong an anchor as the repository name itself. Trusting these directly can allow unauthorized forks/collaborators to impersonate a trusted workflow.
- **Malformed `repo:` claims**: if asserting on the `repo` claim, the value must match the strict `org/repo` format; a malformed or partial match could unintentionally match more repositories than intended.

Since Workload Identity Federation is used specifically so CI/CD pipelines can obtain real GCP credentials without static keys, a loosely-scoped trust condition converts this "keyless" convenience into an open door: any GitHub Actions workflow satisfying the (weak or absent) condition can mint credentials for your GCP service account and act with its permissions — potentially exfiltrating cloud data, modifying infrastructure, or pivoting further into your GCP environment.

## How Checkov evaluates this
The check (`GithubActionsOIDCTrustPolicy`) runs a sequence of validations, short-circuiting to PASS early for providers unrelated to GitHub Actions:
1. If there's no `oidc` block, or its `issuer_uri` is not exactly `https://token.actions.githubusercontent.com`, the check **PASSES** (not applicable — this rule only scrutinizes GitHub Actions OIDC providers).
2. **FAIL** if `attribute_mapping` is missing, or does not contain a `google.subject` mapping.
3. **FAIL** if `attribute_condition` is missing/empty.
4. It extracts the value being compared against `assertion.sub` from the condition string via a regex matching `assertion.sub == '<value>'` (or double quotes). **FAIL** if no such comparison can be extracted.
5. **FAIL** if the extracted value contains no colon (`:`) — GitHub's `sub` claim is structured as `claim_name:claim_value` (e.g. `repo:org/repo:ref:refs/heads/main`), so a value without a colon can't be meaningfully scoping anything.
6. Splits the value on `:`. **FAIL** if the claim name or claim value portion is a wildcard (`*`).
7. **FAIL** if the claim name is one of a known set of "abusable claims" (`gh_abusable_claims`, defined in `checkov.common.util.oidc_utils`) that are not a reliable trust anchor.
8. If the claim name is specifically `repo`, **FAIL** if the repo value doesn't match the expected `org/repo` regex (`gh_repo_regex`).
9. Otherwise, **PASS**.
10. Any exception during evaluation results in **FAIL** (fail-closed).

## Non-compliant example
```hcl
resource "google_iam_workload_identity_pool_provider" "provider_github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }

  attribute_condition = "assertion.sub == 'repo:*'"  # wildcard repo value - matches any repository
}
```

## Remediated example
```hcl
resource "google_iam_workload_identity_pool_provider" "provider_github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }

  attribute_condition = "assertion.sub == 'repo:my-org/robodag:ref:refs/heads/main'"  # <-- scoped to a specific repo and ref
}
```

## Remediation steps
1. Ensure `attribute_mapping` includes `"google.subject" = "assertion.sub"`.
2. Set `attribute_condition` to assert on the `repo:` claim in the `org/repo` format (e.g. `assertion.sub == 'repo:my-org/my-repo:ref:refs/heads/main'`), rather than on the `actor`, `job_workflow_ref`, or other user-influenceable claims.
3. Do not use wildcards (`*`) anywhere in the asserted claim name or value.
4. Prefer scoping to a specific branch/ref or environment in addition to the repo where the workflow triggers sensitive deployments, to reduce risk from unauthorized workflow_dispatch or PR-triggered runs.
5. After changing the condition, run the actual GitHub Actions workflow to confirm the exchange still succeeds, and confirm (in a test environment) that a workflow from a different repo is rejected.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GithubActionsOIDCTrustPolicy.py)
- [GitHub Actions OIDC token claims reference](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [GCP Workload Identity Federation with GitHub Actions](https://cloud.google.com/blog/products/identity-security/enabling-keyless-authentication-from-github-actions)
