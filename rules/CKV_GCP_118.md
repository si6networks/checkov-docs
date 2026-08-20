# CKV_GCP_118: Ensure IAM workload identity pool provider is restricted

## Severity
**HIGH** (score: 7.5/10)

Without an attribute_condition, a workload identity pool provider trusts any token from the configured external issuer (e.g. any GitHub Actions workflow in any repo), letting an unrelated third party impersonate the mapped GCP service account.

## Summary
This check fails when a `google_iam_workload_identity_pool_provider` resource does not set an `attribute_condition`, meaning any external identity that can obtain a token from the configured issuer (e.g. any GitHub Actions workflow, in any repository) can assume the associated GCP service account.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_iam_workload_identity_pool_provider`
- **Check type:** resource (value check)

## Why it matters
Workload Identity Federation lets external identity providers (GitHub Actions OIDC, AWS, Azure AD, etc.) exchange a short-lived token for GCP credentials without needing a long-lived service account key. This is a security improvement over static keys, but it introduces a new trust boundary: GCP will trust *any* token from the configured issuer unless the `attribute_condition` narrows down which subjects/claims are acceptable.

Concretely, if you configure a workload identity pool provider trusting `https://token.actions.githubusercontent.com` (GitHub Actions' OIDC issuer) without an `attribute_condition`, then **any GitHub Actions workflow, in any repository, in any organization** that references your provider resource name can obtain the mapped service account's credentials. An attacker who discovers your workload identity provider's resource path (which is often not secret — it may appear in public CI configs, blog posts, or be guessable) could run a workflow in their own unrelated repo and impersonate your service account, then act with its GCP permissions. This is a documented real-world attack pattern against misconfigured Workload Identity Federation.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` (value check):
- **Inspected key:** `attribute_condition`
- **Expected value:** `ANY_VALUE` (i.e., the check just requires the attribute to be set to *something* non-empty — it does not validate the specific condition logic, e.g. it doesn't confirm the condition actually restricts by repo).
- **PASS** if `attribute_condition` is present and set to any value.
- **FAIL** if `attribute_condition` is missing entirely.

Note: setting *any* condition string satisfies this specific check; it does not verify the condition is a strong/correct restriction (that stronger validation is what `CKV_GCP_125` does specifically for GitHub Actions issuers).

## Non-compliant example
```hcl
resource "google_iam_workload_identity_pool_provider" "github_provider" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  # no attribute_condition set - any GitHub Actions run anywhere can authenticate
}
```

## Remediated example
```hcl
resource "google_iam_workload_identity_pool_provider" "github_provider" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }

  attribute_condition = "assertion.repository == 'my-org/my-repo'"  # <-- restricts to a specific repo
}
```

## Remediation steps
1. Add an `attribute_condition` to every `google_iam_workload_identity_pool_provider`.
2. For GitHub Actions, scope the condition to the specific repository (and optionally branch/environment/ref) using claims like `assertion.repository == 'org/repo'` or `assertion.sub.startsWith('repo:org/repo:ref:refs/heads/main')`.
3. Avoid wildcard conditions (e.g. `assertion.repository_owner == '*'` or matching on claims that are attacker-controllable, like arbitrary job names).
4. See also `CKV_GCP_125` for a deeper check of GitHub-Actions-specific condition correctness (must scope on `repo:` claim, not use abusable claims, not use wildcards).
5. Test by running the actual CI workflow after the change to confirm it can still authenticate, and attempt (in a controlled way) to authenticate from an unrelated repo to confirm it's now rejected.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleIAMWorkloadIdentityConditional.py)
- [GCP Workload Identity Federation attribute conditions](https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)
- Referenced in source: https://www.revblock.dev/exploiting-misconfigured-google-cloud-service-accounts-from-github-actions/
