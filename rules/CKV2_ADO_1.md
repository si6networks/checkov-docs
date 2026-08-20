# CKV2_ADO_1: Ensure at least two approving reviews for PRs

## Severity
**MEDIUM** (score: 4.5/10)

Missing a two-reviewer approval gate on pull requests weakens code-review controls against unauthorized or malicious changes reaching protected branches, but it is a process control rather than a direct technical exploit path.

## Summary
This check ensures that every Azure DevOps Git repository has a branch policy requiring at least two approving reviewers before a pull request can be completed.

## Applicability
**Checkov framework(s):** `terraform`

Terraform (Azure DevOps provider). Applies to `azuredevops_git_repository` resources, verified in connection with an `azuredevops_branch_policy_min_reviewers` resource.

## Why it matters
A pull-request review gate is one of the primary controls against malicious or accidental changes reaching a protected branch (e.g. `main`/`release`). If a repository has no minimum-reviewer policy, or the policy is set to fewer than two reviewers, a single compromised or careless account can merge code — including backdoors, credential leaks, or broken infrastructure changes — without a second set of eyes. Requiring two approvals raises the bar for both insider threats and simple mistakes, and is a common baseline control in SOC2/ISO27001-style change-management requirements.

## How Checkov evaluates this
This is a graph-based (JSON) policy, not a Python check. It performs two things:
1. **Connection check**: confirms an `azuredevops_git_repository` resource is connected to an `azuredevops_branch_policy_min_reviewers` resource (i.e., the repo actually has a min-reviewers policy attached at all).
2. **Attribute check**: on that `azuredevops_branch_policy_min_reviewers` resource, it inspects `settings.reviewer_count` and requires it to be `>= 2`.

If no `azuredevops_branch_policy_min_reviewers` is connected to the repository, or the connected policy's `reviewer_count` is less than 2, the check **FAILS**. If a policy exists and `reviewer_count >= 2`, it **PASSES**.

## Non-compliant example
```hcl
resource "azuredevops_git_repository" "repo" {
  project_id = azuredevops_project.example.id
  name       = "example-repo"
  initialization {
    init_type = "Clean"
  }
}

resource "azuredevops_branch_policy_min_reviewers" "min_reviewers" {
  project_id = azuredevops_project.example.id

  enabled  = true
  blocking = true

  settings {
    reviewer_count     = 1
    submitter_can_vote = false

    scope {
      repository_id  = azuredevops_git_repository.repo.id
      repository_ref = "refs/heads/main"
      match_type     = "Exact"
    }
  }
}
```

## Remediated example
```hcl
resource "azuredevops_git_repository" "repo" {
  project_id = azuredevops_project.example.id
  name       = "example-repo"
  initialization {
    init_type = "Clean"
  }
}

resource "azuredevops_branch_policy_min_reviewers" "min_reviewers" {
  project_id = azuredevops_project.example.id

  enabled  = true
  blocking = true

  settings {
    reviewer_count     = 2   # <-- fixed: require at least two approvals
    submitter_can_vote = false

    scope {
      repository_id  = azuredevops_git_repository.repo.id
      repository_ref = "refs/heads/main"
      match_type     = "Exact"
    }
  }
}
```

## Remediation steps
1. Add an `azuredevops_branch_policy_min_reviewers` resource for every `azuredevops_git_repository` that doesn't already have one.
2. Set `settings.reviewer_count = 2` (or higher, per your compliance requirements).
3. Set `blocking = true` so the policy actually prevents PR completion when unmet, and `enabled = true`.
4. Scope the policy to the protected branch(es) (e.g. `refs/heads/main`) via the `scope` block.
5. Consider also setting `submitter_can_vote = false` so the PR author's own approval doesn't count toward the minimum.
6. Verify in Azure DevOps > Repos > Branches > Branch policies that the policy is active after apply.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/azuredevops/ADORepositoryHasMinTwoReviewers.json
