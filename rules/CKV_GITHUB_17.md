# CKV_GITHUB_17: Ensure GitHub branch protection requires push restrictions
## Severity
**HIGH** (score: 7.5/10)

Without push restrictions on a protected branch, any collaborator with write access can push commits directly to that branch, entirely bypassing pull-request review and status-check controls.

## Summary
This check fails when a branch protection rule does not define push `restrictions`, meaning any collaborator with write access to the repository can push directly to the protected branch rather than only a defined, limited set of users/teams/apps.

## Applicability
**Checkov framework(s):** `github_configuration`

- **Framework:** GitHub repository configuration (`github_configuration` — branch protection settings)
- **Entities:** `*`, evaluated against the `restrictions` field

## Why it matters
Even with required PR reviews configured, if direct push restrictions aren't set, every collaborator with write access may still be able to push commits straight to the protected branch through certain paths (e.g., merge commits, or on plans/configurations where push restriction and required-review settings interact differently), and — more importantly — the "who can push directly" question is a distinct control from "who must review PRs." Restricting pushes to a named allowlist of users, teams, or GitHub Apps ensures that only a small, accountable group can ever land code on the branch without going through the standard contribution path, reducing the blast radius if any single non-privileged collaborator's account or token is compromised, and making it possible to build automation (bots, release tooling) with tightly scoped, auditable push rights instead of broad repository write access.

## How Checkov evaluates this
This is a `BranchSecurity`-based check (`GithubBranchRequirePushRestrictions`) evaluating the `restrictions` key on the branch protection rule. If this field is present/truthy (push restrictions are configured), the check **PASSES**; if absent, the check **FAILS**.

## Non-compliant example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1
  }
}
```
No `restrictions` block — push restrictions are not configured, so (subject to your plan and other settings) a broader set of collaborators may have direct push capability.

## Remediated example
```json
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 1
  },
  "restrictions": {
    "users": [],
    "teams": ["release-engineers"],
    "apps": ["release-bot"]
  }
}
```

## Remediation steps
1. Go to **Settings → Branches**, edit the branch protection rule, and enable **"Restrict who can push to matching branches"**, then add only the specific users, teams, or apps that should be allowed.
2. Note this feature is only available on GitHub Team/Enterprise plans for organization-owned repositories.
3. If using Terraform's `github_branch_protection` resource, set the `restrictions` (or `push_restrictions`) block to the intended allowlist.
4. Prefer scoping this to automation identities (bots/apps) and a minimal set of release engineers rather than broad teams.
5. Periodically review the allowlist as team composition and release processes change.
6. Re-run Checkov to confirm the `restrictions` field is configured.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/github/checks/require_push_restrictions.py
- GitHub documentation on branch protection push restrictions: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
