# CKV2_GIT_1: Ensure each Repository has branch protection associated

## Severity
**MEDIUM** (score: 5.5/10)

Lacking branch protection allows force-pushes, unreviewed merges, or history rewrites on critical branches, weakening change-control integrity though it does not directly expose data or credentials.

## Summary
This check ensures that every `github_repository` resource managed in Terraform has an associated branch protection configuration (via `github_branch_protection`, `github_branch_protection_v3`, or `github_repository_ruleset`), so that at least one branch (typically the default branch) is protected from unreviewed direct pushes or deletion.

## Applicability
- **IaC framework:** Terraform (GitHub provider)
- **Resource type:** `github_repository` (connection checked against `github_branch_protection`, `github_branch_protection_v3`, `github_repository_ruleset`)

This is a graph-based check (Checkov "graph check", defined as JSON, scoped to the `GITHUB` provider) that inspects connections between a repository resource and any branch-protection or ruleset resource, rather than validating attributes on a single resource.

## Why it matters
Without branch protection, any collaborator with write access to a repository can push directly to the default branch (e.g., `main`), force-push to rewrite history, delete the branch, or merge a pull request without any required review or passing status checks. This removes essential guardrails: malicious or accidental commits can land in production-facing code without a second set of eyes, CI results can be bypassed, and history can be rewritten to hide unauthorized changes — undermining code-review-based security controls, audit trails, and supply-chain integrity (e.g., for repositories that feed CI/CD pipelines or produce released artifacts).

## How Checkov evaluates this
The check filters for `github_repository` resources and requires a **connection** to exist from that repository to at least one of: `github_branch_protection`, `github_branch_protection_v3`, or `github_repository_ruleset`. If no such connected resource exists anywhere in the Terraform configuration graph, the check **fails**. If any of these protection/ruleset resources is connected to the repository, the check **passes** — the check does not further validate the specific protection rules configured (e.g., required reviewers count, required status checks) — it only confirms that *some* protection mechanism is attached.

## Non-compliant example
```hcl
resource "github_repository" "app" {
  name       = "sec-test-skel"
  visibility = "private"
}

# No github_branch_protection, github_branch_protection_v3,
# or github_repository_ruleset resource defined anywhere for this repo.
```

## Remediated example
```hcl
resource "github_repository" "app" {
  name       = "sec-test-skel"
  visibility = "private"
}

resource "github_branch_protection" "main" {
  repository_id = github_repository.app.node_id
  pattern       = "main"

  required_status_checks {
    strict   = true
    contexts = ["ci/lint", "ci/test"]
  }

  required_pull_request_reviews {
    required_approving_review_count = 1
    dismiss_stale_reviews           = true
  }

  enforce_admins = true
}
```

## Remediation steps
1. Add a `github_branch_protection` (or `github_repository_ruleset` for the newer, more flexible ruleset API) resource targeting the repository's default branch (commonly `main` or `master`).
2. Require pull request reviews (`required_pull_request_reviews`) with at least one approving reviewer, and enable `dismiss_stale_reviews` so approvals don't survive new pushes.
3. Require passing status checks (`required_status_checks`) for CI/lint/test jobs before merge is allowed.
4. Set `enforce_admins = true` (or the ruleset equivalent) so the protection also applies to repository admins, not just regular collaborators.
5. Consider `github_repository_ruleset` instead of the older branch-protection resources if you need more granular controls (e.g., protecting multiple branch patterns, bypass lists, or tag protections) — Checkov accepts any of the three as satisfying this check.
6. Apply and verify via the GitHub UI (Settings > Branches) that the protection rule is active on the intended branch.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/github/RepositoryHasBranchProtection.json
- GitHub docs: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
