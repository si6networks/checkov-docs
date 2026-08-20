# CKV2_AWS_14: Ensure that IAM groups includes at least one IAM user

## Severity
**LOW** (score: 2.0/10)

An IAM group with no members is an unused artifact and organizational hygiene issue with no direct exploitable exposure.

## Summary
This check ensures that every IAM group defined in Terraform actually has at least one IAM user assigned to it via an `aws_iam_group_membership` resource.

## Applicability
**Checkov framework(s):** `terraform`

Terraform (AWS provider). Applies to `aws_iam_group` resources, evaluated in connection with `aws_iam_group_membership` (which itself connects to `aws_iam_user`).

## Why it matters
An IAM group with permissions/policies attached but no members is dead configuration — it doesn't grant excess access by itself, but it's a signal of drift or an incomplete rollout: perhaps users were meant to be added but the membership resource was never written or was accidentally removed, meaning the intended access-control model isn't actually in effect. More importantly, from an IaC hygiene and auditing perspective, orphaned groups make it harder to reason about "who actually has what access," complicating access reviews and increasing the chance that a *future* change silently grants broad permissions to a user added to a powerful group without anyone verifying that's intentional. This check is mainly a completeness/quality control ensuring the IAM model expressed in code matches an operative state.

## How Checkov evaluates this
This is a graph-based (JSON) policy that filters on `aws_iam_group_membership` resources and requires ALL of:
1. The `aws_iam_group` is connected to an `aws_iam_group_membership` resource.
2. That `aws_iam_group_membership` is connected to an `aws_iam_user` resource.
3. The `aws_iam_group_membership` resource's `users` attribute exists (i.e., it lists at least one user).

If a group has no `aws_iam_group_membership` resource at all, or that membership resource has an empty/absent `users` list, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_iam_group" "developers" {
  name = "developers"
}

resource "aws_iam_group_policy_attachment" "dev_policy" {
  group      = aws_iam_group.developers.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}
# No aws_iam_group_membership resource assigning any user to this group
```

## Remediated example
```hcl
resource "aws_iam_user" "alice" {
  name = "alice"
}

resource "aws_iam_group" "developers" {
  name = "developers"
}

resource "aws_iam_group_policy_attachment" "dev_policy" {
  group      = aws_iam_group.developers.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_iam_group_membership" "developers_membership" {   # <-- fixed: group has a member
  name  = "developers-membership"
  group = aws_iam_group.developers.name
  users = [aws_iam_user.alice.name]
}
```

## Remediation steps
1. For every `aws_iam_group`, add a corresponding `aws_iam_group_membership` (or use `aws_iam_user_group_membership` on the user side) listing the IAM users that should belong to it.
2. If a group is genuinely not yet in use, consider whether it should exist in code at all — remove unused groups rather than leaving placeholders.
3. Prefer `aws_iam_user_group_membership` (managed per-user) over `aws_iam_group_membership` (which fully replaces a group's membership list) if multiple Terraform configs/modules manage users independently, to avoid one apply wiping out another's membership additions.
4. Periodically audit IAM groups against actual membership as part of access reviews, since Terraform will happily apply an empty/near-empty group indefinitely without this check.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/IAMGroupHasAtLeastOneUser.json
