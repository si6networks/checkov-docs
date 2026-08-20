# CKV_AZURE_249: Ensure Azure GitHub Actions OIDC trust policy is configured securely

## Severity
**HIGH** (score: 7.5/10)

A loosely-scoped OIDC federated identity subject claim (wildcards or abusable claim types) lets an attacker who can trigger a workflow in an unrelated or forked repository mint tokens that impersonate the Azure AD application and pivot into the subscription, a well-documented supply-chain takeover path.

## Summary
This check validates that Azure AD Workload Identity Federation credentials for GitHub Actions (`azuread_application_federated_identity_credential`) have a `subject` claim that is scoped tightly enough to prevent unintended repositories, branches, or actors from assuming the federated identity.

## Applicability
- **Framework:** Terraform
- **Resource type:** `azuread_application_federated_identity_credential`

## Why it matters
OIDC federation between GitHub Actions and Azure AD lets workflows obtain Azure credentials without storing long-lived secrets — but the security of the entire trust relationship boils down to how narrowly the `subject` claim is scoped. A poorly-scoped subject (e.g., a wildcard, or a claim type known to be abusable such as `pull_request` in some configurations) means that any workflow — including one triggered by an external contributor's pull request, or one running in an unrelated repository — could obtain a token matching the trust policy and impersonate the Azure AD application. This is a well-documented supply-chain attack vector: an attacker who can trigger a GitHub Actions run matching the loose subject pattern (e.g., via a PR from a fork) can mint federated tokens and pivot into the victim's Azure subscription. Requiring a well-formed `repo:<owner>/<name>:...` subject (no wildcards, no known-abusable claim types) keeps the trust scoped to a specific repository and ref/environment.

## How Checkov evaluates this
The check (`BaseResourceCheck`) inspects the `subject` attribute of the federated identity credential:
1. **FAIL** if `subject` is empty/missing.
2. **FAIL** if the subject doesn't contain a colon (`:`) — GitHub Actions subject claims are colon-delimited (e.g., `repo:org/name:ref:refs/heads/main`), so this indicates a malformed or overly generic value; a bare `"*"` also fails this check.
3. Split the subject on `:`. **FAIL** if the first or second colon-delimited segment is a wildcard `*`.
4. **FAIL** if the first segment (the claim type, e.g. `repo`, `pull_request`, `environment`) is in the internal `gh_abusable_claims` list of claim types considered too permissive/exploitable for a security-sensitive trust relationship.
5. If the claim type is `repo`, **FAIL** unless the second segment matches `gh_repo_regex` — the expected `owner/name` repository pattern.
6. Any parsing exception also results in **FAIL**.
7. Otherwise, **PASS**.

## Non-compliant example
```hcl
resource "azuread_application_federated_identity_credential" "github_actions" {
  application_id = azuread_application.example.id
  display_name   = "github-actions-oidc"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:*:ref:refs/heads/main"   # wildcard repo owner/name
}
```

## Remediated example
```hcl
resource "azuread_application_federated_identity_credential" "github_actions" {
  application_id = azuread_application.example.id
  display_name   = "github-actions-oidc"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:my-org/my-repo:ref:refs/heads/main"  # scoped to exact repo + branch
}
```

## Remediation steps
1. Replace any wildcard (`*`) segments in the `subject` claim with the exact repository owner/name.
2. Scope the trust to a specific ref, branch, tag, or GitHub `environment` (e.g., `repo:org/repo:environment:production`) rather than trusting all refs.
3. Avoid claim types flagged as abusable (e.g., avoid trusting solely on `pull_request` events, which can be triggered by external/fork contributors without write access).
4. Ensure the repository segment matches the standard `owner/name` format expected by GitHub's OIDC subject claims.
5. Regularly audit federated credentials tied to production-scoped Azure AD applications/service principals, since an overly broad trust policy is invisible until exploited.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/GithubActionsOIDCTrustPolicy.py)
- [GitHub Actions OIDC claims reference](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
