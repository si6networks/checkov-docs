# CKV2_AWS_37: Ensure CodeCommit associates an approval rule
## Severity
**LOW** (score: 2.0/10)

Lack of a mandatory code-review/approval rule on a source repository allows unreviewed code (including malicious or compromised commits) to merge directly, a supply-chain integrity risk that depends on a prior insider or credential compromise to exploit.

## Summary
This check ensures that every `aws_codecommit_repository` has an associated approval rule template (via `aws_codecommit_approval_rule_template_association`), so that pull requests against the repository require an approval rule (e.g., minimum number of approvers) before merging.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_codecommit_repository` (connected `aws_codecommit_approval_rule_template_association`)
- **Category:** General security

## Why it matters
A source code repository with no mandatory approval workflow allows any contributor with write access to merge code directly with no independent review. This creates a significant risk vector: malicious or compromised commits (e.g., an insider threat, or an attacker who has stolen a developer's credentials/SSH key) can be merged straight into protected branches — including a backdoor, a supply-chain-poisoning dependency change, or a CI/CD pipeline modification — with no second set of eyes to catch it before it reaches production. Mandatory approval rules (requiring a minimum number of approvers, or approval from specific roles/teams) are a foundational software-supply-chain control, aligning with frameworks like SLSA and standard separation-of-duties requirements common in SOC 2 / PCI DSS audits, which typically require that no single individual can unilaterally introduce and merge changes into critical branches.

## How Checkov evaluates this
This is a graph check (`CodecommitApprovalRulesAttached.json`). It filters resources of type `aws_codecommit_repository`, and requires a graph connection to exist between that repository and an `aws_codecommit_approval_rule_template_association` resource. It does not inspect the content of the approval rule template itself (e.g., how many approvers are required) — only that some approval rule template has been associated with the repository at all. A repository with no associated `aws_codecommit_approval_rule_template_association` resource fails.

## Non-compliant example
```hcl
resource "aws_codecommit_repository" "app_repo" {
  repository_name = "app-source"
  description     = "Main application source repository"
}
# No approval rule template association — PRs can be merged with no required review
```

## Remediated example
```hcl
resource "aws_codecommit_repository" "app_repo" {
  repository_name = "app-source"
  description     = "Main application source repository"
}

resource "aws_codecommit_approval_rule_template" "require_two_approvers" {
  name        = "require-two-approvers"
  description = "Require at least 2 approvals before merging"

  content = jsonencode({
    Version               = "2018-11-08"
    DestinationReferences = ["refs/heads/main"]
    Statements = [{
      Type                    = "Approvers"
      NumberOfApprovalsNeeded = 2
      ApprovalPoolMembers     = ["arn:aws:sts::123456789012:assumed-role/CodeCommitApprovers/*"]
    }]
  })
}

# The association satisfies the check
resource "aws_codecommit_approval_rule_template_association" "app_repo_assoc" {
  approval_rule_template_name = aws_codecommit_approval_rule_template.require_two_approvers.name
  repository_name              = aws_codecommit_repository.app_repo.repository_name
}
```

## Remediation steps
1. Define an `aws_codecommit_approval_rule_template` specifying the approval requirements (number of approvers, approval pool members/roles, and target branch references via `DestinationReferences`).
2. Add an `aws_codecommit_approval_rule_template_association` linking the template to the repository.
3. Consider centralizing one or a small number of approval rule templates and associating them with all repositories in the organization, rather than defining a bespoke template per repo, for consistency and easier auditing.
4. Combine this with branch protection (`aws_codecommit_repository` doesn't natively support branch protection the way GitHub does, so approval rule templates are the primary mechanism CodeCommit offers) to ensure the `main`/`master` branch specifically requires approval.
5. Note: if your organization has migrated away from AWS CodeCommit (AWS announced it is no longer accepting new customers as of mid-2024), this check may be less relevant going forward — evaluate whether equivalent controls (required PR reviews, branch protection rules) are correctly configured in your actual VCS (GitHub, GitLab, Bitbucket) instead.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/CodecommitApprovalRulesAttached.json)
- [AWS CodeCommit approval rule templates documentation](https://docs.aws.amazon.com/codecommit/latest/userguide/approval-rule-templates.html)
