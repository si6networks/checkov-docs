# CKV_AWS_257: Ensure CodeCommit branch changes have at least 2 approvals

## Severity
**LOW** (score: 2.0/10)

Allowing CodeCommit merges with fewer than two approvals weakens code-review governance and increases the chance a single compromised or malicious approver can introduce unreviewed changes, an insider/process risk rather than a directly exploitable technical flaw.

## Summary
This check ensures that an AWS CodeCommit approval rule template requires a minimum of 2 approvals (`NumberOfApprovalsNeeded >= 2`) before a pull request can be merged.

## Applicability
- **Framework:** Terraform
- **Resource type:** `aws_codecommit_approval_rule_template`

## Why it matters
A code review/approval gate with only a single required approver (or none at all) means a single compromised or malicious account with write access can merge arbitrary code changes — including backdoors, credential exfiltration, or supply-chain tampering — without any independent second reviewer catching it. Requiring at least two approvals implements a basic two-person-integrity control: it raises the bar for both insider threats (a lone rogue developer cannot unilaterally merge) and account-compromise scenarios (an attacker who has taken over one developer's credentials still cannot merge without a second, presumably uncompromised, reviewer approving). This is a standard software supply-chain security control recommended by frameworks like SLSA and NIST SSDF for any repository housing production code or infrastructure.

## How Checkov evaluates this
The check parses the JSON `content` attribute of the approval rule template:

```
content -> Statements[0] -> NumberOfApprovalsNeeded
```

- **PASS**: `NumberOfApprovalsNeeded` is an integer and `>= 2`.
- **FAIL**: otherwise — including when `content`/`Statements` is missing, malformed, not a dict, or `NumberOfApprovalsNeeded` is less than 2 or not an integer.

## Non-compliant example
```hcl
resource "aws_codecommit_approval_rule_template" "example" {
  name        = "example-approval-rule"
  description = "Require approval before merge"

  content = jsonencode({
    Version               = "2018-11-08"
    DestinationReferences = ["refs/heads/main"]
    Statements = [{
      Type                    = "Approvers"
      NumberOfApprovalsNeeded = 1   # only a single approver required
      ApprovalPoolMembers     = ["arn:aws:sts::123456789012:assumed-role/CodeCommitReview/*"]
    }]
  })
}
```

## Remediated example
```hcl
resource "aws_codecommit_approval_rule_template" "example" {
  name        = "example-approval-rule"
  description = "Require approval before merge"

  content = jsonencode({
    Version               = "2018-11-08"
    DestinationReferences = ["refs/heads/main"]
    Statements = [{
      Type                    = "Approvers"
      NumberOfApprovalsNeeded = 2   # <-- raised to minimum of 2
      ApprovalPoolMembers     = ["arn:aws:sts::123456789012:assumed-role/CodeCommitReview/*"]
    }]
  })
}
```

## Remediation steps
1. Locate the `content` JSON of each `aws_codecommit_approval_rule_template` resource.
2. Set `NumberOfApprovalsNeeded` to `2` or higher within the `Statements` array.
3. Ensure the approval rule template is actually **associated** with the target repositories (`aws_codecommit_approval_rule_template_association`) — defining the template alone doesn't enforce it until associated.
4. Make sure `ApprovalPoolMembers` includes enough distinct reviewers that the 2-approval requirement is practically achievable without becoming a bottleneck (e.g., a whole team/role ARN pattern rather than two specific named individuals).
5. Combine with branch protection (disallowing self-approval where possible) for a complete two-person-review control.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/CodecommitApprovalsRulesRequireMin2.py)
- [AWS: CodeCommit approval rule templates](https://docs.aws.amazon.com/codecommit/latest/userguide/approval-rule-templates.html)
