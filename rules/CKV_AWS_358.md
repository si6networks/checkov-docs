# CKV_AWS_358: Ensure AWS GitHub Actions OIDC authorization policies only allow safe claims and claim order

## Severity
**HIGH** (score: 7.5/10)

A missing or wildcarded `sub` condition on a GitHub Actions OIDC trust policy lets any GitHub Actions workflow (or an attacker-controlled fork/branch/environment) assume the AWS role, a classic confused-deputy trust-boundary bypass that can lead directly to account compromise.

## Summary
This check validates that IAM trust policies (`aws_iam_policy_document`) federating trust to GitHub Actions' OIDC provider (`token.actions.githubusercontent.com`) constrain the `sub` claim with a condition that cannot be trivially satisfied by an attacker-controlled repository, branch, or environment name.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Check type:** data source check
- **Entities:** `aws_iam_policy_document` (specifically statements whose `principals` block federates to a `Federated` identifier containing `oidc-provider/token.actions.githubusercontent.com`)

## Why it matters
AWS supports federating IAM role trust to GitHub Actions' OIDC identity provider so that workflows can assume roles without long-lived AWS credentials. The security of this model rests entirely on the `condition` block of the trust policy, which restricts which GitHub `sub` (subject) claims — and therefore which repositories, branches, tags, or environments — may assume the role.

If the policy has no condition at all, or the condition uses a bare wildcard (`sub: *`), *any* GitHub Actions workflow anywhere on GitHub.com that can obtain an OIDC token can potentially assume the role — a classic "confused deputy" / overly-permissive trust boundary. Even subtler misconfigurations are dangerous: if the condition only inspects the first claim segment (e.g. matches on `repo:org/name` but allows an arbitrary suffix via `*` in the ref/environment position), an attacker who controls a branch name, a forked PR, or a self-registered environment in the same repo can craft a `sub` value that satisfies the condition and impersonate a trusted workflow, then assume the AWS role and pivot into the account. GitHub-hosted claims like `pull_request` are also considered "abusable" because they can be triggered by external, unprivileged contributors via a fork's pull request.

## How Checkov evaluates this
The check (`GithubActionsOIDCTrustPolicy`) inspects each `statement` block in the `aws_iam_policy_document`:
1. It scans `principals` for a `Federated` principal type whose `identifiers` contain `oidc-provider/token.actions.githubusercontent.com`. If none is found, the statement is not a GitHub OIDC trust statement and the check **PASSES**.
2. If a GitHub OIDC federated principal is found but the statement has **no `condition` block at all**, the check **FAILS**.
3. For statements that do have conditions, it looks for a condition variable matching the GitHub `sub` condition pattern (`gh_sub_condition`, e.g. `token.actions.githubusercontent.com:sub`).
4. For each matching condition's `values`:
   - If the value is a bare wildcard (`["*"]`), it **FAILS** (matches literally anything).
   - The value is split on `:`. If splitting produces only one segment (i.e., the assertion isn't of the form `{claim_name}:{claim_value}`, such as `repo:org/repo`), it **FAILS**.
   - If the claim value portion itself is `*` (e.g. `repo:*`), it **FAILS**.
   - If the claim name (first segment, e.g. `pull_request`) is one of a known list of "abusable" GitHub claims (claims that can be influenced by untrusted/external actors, such as `pull_request`), it **FAILS**.
5. Otherwise (a properly scoped `repo:org/name:ref:refs/heads/main`-style condition on a safe claim), it **PASSES**.

## Non-compliant example
```hcl
data "aws_iam_policy_document" "github_oidc_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # No condition scoping the `sub` claim at all -> unrestricted trust
  }
}
```

## Remediated example
```hcl
data "aws_iam_policy_document" "github_oidc_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      # Pinned to a specific repo and branch, not a wildcard or abusable claim
      values   = ["repo:my-org/my-repo:ref:refs/heads/main"]
    }
  }
}
```

## Remediation steps
1. Always add a `condition` block on any trust statement that federates to `token.actions.githubusercontent.com`.
2. Scope the `sub` condition to `repo:<org>/<repo>:ref:refs/heads/<branch>` (or `:environment:<name>`) rather than a bare wildcard.
3. Never use `repo:*` or `sub: *` — this allows any GitHub repository in existence to assume the role.
4. Avoid conditioning on `pull_request` or other claims that untrusted external contributors can trigger (e.g., via a forked PR) — prefer `ref` or `environment`-based claims tied to protected branches/environments.
5. Also validate the `aud` claim is `sts.amazonaws.com` to prevent token reuse from other relying parties.
6. Consider using GitHub's `environment` protection rules (required reviewers) in combination with the `environment:` claim for the highest-privilege roles.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/GithubActionsOIDCTrustPolicy.py
- AWS docs: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
- GitHub docs: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services
