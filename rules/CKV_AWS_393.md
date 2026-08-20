# CKV_AWS_393: Ensure AWS GitHub Actions OIDC authorization policies only allow safe claims and claim order on IAM role
## Severity
**HIGH** (score: 7.5/10)

Unsafe GitHub Actions OIDC trust conditions on an IAM role can allow workflows from unintended repositories, branches, or forks to assume the role, enabling unauthorized privilege escalation into the AWS account.

## Summary
This check inspects the inline `assume_role_policy` (trust policy) of an `aws_iam_role` for statements that federate trust to GitHub Actions' OIDC provider, and fails if the `sub` (subject) claim condition is missing or written in a way that can be bypassed (wildcards, missing claim segments, or unsafe claim ordering).

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_iam_role` (specifically its `assume_role_policy` attribute)

This check is the resource-level counterpart to `CKV_AWS_358`, which performs the same analysis on `data "aws_iam_policy_document"` blocks used to build a trust policy; this rule instead handles roles whose trust policy is written as an inline JSON document directly in `assume_role_policy`.

## Why it matters
GitHub Actions supports OpenID Connect (OIDC) federation, letting workflows assume an AWS IAM role without long-lived static credentials. AWS trusts any JWT signed by GitHub's OIDC provider whose claims satisfy the role's trust-policy `Condition`. The `sub` claim in that JWT typically looks like `repo:ORG/REPO:ref:refs/heads/main` or `repo:ORG/REPO:environment:prod`. If the trust policy's condition on `sub`:
- Is **missing entirely** — any GitHub Actions workflow in the world (from any repo, any org) that can reach the OIDC token can assume the role.
- Uses a **bare wildcard** (`"sub": "*"`) — same problem, effectively no restriction.
- Has a **malformed/incomplete claim** (e.g., just `"invalid"` with no colon-delimited structure) — the condition doesn't actually constrain anything meaningful.
- Uses a **wildcard on the repo/org segment** (e.g., `"repo:*:ref:refs/heads/main"`) — any organization's repository can satisfy the condition, not just your own.

Any of these effectively turns the trust relationship into "any GitHub Actions workflow anywhere can assume this AWS role," which is a critical privilege-escalation and lateral-movement risk — any public repository (including ones unrelated to your org) could potentially forge a matching OIDC token and assume your IAM role.

## How Checkov evaluates this
The Python `BaseResourceCheck` parses the `assume_role_policy` JSON on `aws_iam_role`:
1. If there's no `assume_role_policy`, or it can't be parsed as a policy dict, or it has no `Statement` — **PASS** (nothing to evaluate).
2. For each statement: if the statement's `Principal.Federated` does **not** reference `oidc-provider/token.actions.githubusercontent.com`, the check has nothing to say about GitHub OIDC and returns **PASS**.
3. If a GitHub-OIDC federated principal *is* found:
   - If the statement has **no `Condition` block at all** → **FAIL**.
   - Otherwise, the check walks all condition operators looking for a variable name matching the `:sub` claim pattern (e.g., `token.actions.githubusercontent.com:sub`).
   - Each string value found for that `:sub` condition is classified as unsafe/safe:
     - `"*"` (bare wildcard) → **FAIL**
     - A value with no colon (e.g., `"invalid"`, no `repo:org/repo:...` structure) → **FAIL**
     - A wildcard on the first claim segment (e.g., `"claim:*"`, meaning the org/repo portion is wildcarded) → **FAIL** (per the referenced logic; additional unsafe patterns are checked in the same order as sibling check CKV_AWS_358)
     - A well-formed, specific `repo:ORG/REPO:...` value → **PASS**
   - If a `Condition` exists but **no operator contains a `:sub` claim constraint at all**, the check falls through to **FAIL** (a condition exists but doesn't actually restrict the subject claim).

## Non-compliant example
```hcl
resource "aws_iam_role" "gha_deploy" {
  name = "gha-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        # No Condition at all: any GitHub Actions workflow, any org, any repo can assume this role
      }
    ]
  })
}
```

## Remediated example
```hcl
resource "aws_iam_role" "gha_deploy" {
  name = "gha-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            # Restricted to a specific org/repo and branch — no wildcards on the repo segment
            "token.actions.githubusercontent.com:sub" = "repo:my-org/my-repo:ref:refs/heads/main"
          }
        }
      }
    ]
  })
}
```

## Remediation steps
1. Always include a `Condition` on any trust-policy statement that federates to `token.actions.githubusercontent.com`.
2. Constrain the `:sub` claim to a specific `repo:ORG/REPO:...` value (branch, tag, environment, or pull_request qualifier) — never a bare `*` and never a wildcard on the org/repo portion.
3. Also constrain the `:aud` claim to `sts.amazonaws.com` (standard practice, though not the focus of this specific check).
4. Prefer `StringEquals` for exact matches; if using `StringLike` for wildcards, ensure wildcards only apply to the trailing ref/branch/environment segment, never the leading `repo:ORG/REPO` segment.
5. Review any existing roles trusting the GitHub OIDC provider for overly broad conditions, especially roles created before your org standardized on scoped trust policies.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/GithubActionsOIDCTrustPolicyOnRole.py)
- [GitHub Actions: configuring OpenID Connect in AWS](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
