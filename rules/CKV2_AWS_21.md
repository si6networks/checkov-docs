# CKV2_AWS_21: Ensure that all IAM users are members of at least one IAM group
## Severity
**LOW** (score: 2.0/10)

Standalone IAM users without group-based permission management increase the risk of inconsistent, hard-to-audit, or excessive permission grants over time, but this alone does not directly expose credentials or grant dangerous access.

## Summary
This check ensures every `aws_iam_user` defined in Terraform is attached to at least one IAM group via `aws_iam_group_membership`, rather than having permissions assigned individually to the user.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_iam_user` (the entity being validated), `aws_iam_group_membership` (the connecting resource), and transitively `aws_iam_group`
- **Check type:** Graph-based connection check (evaluates relationships between resources across the Terraform configuration, not a single resource's attributes)

## Why it matters
Attaching policies directly to individual IAM users instead of managing permissions through groups is a common cause of permission sprawl and drift. When users are not grouped, every access change requires touching each user resource individually, which leads to inconsistent policies across users doing the same job, forgotten permission revocations when someone changes roles, and no single place to audit "what can this team do." AWS's own IAM best practices recommend grouping users so that permissions are defined once per group and inherited, making access reviews, least-privilege enforcement, and offboarding (removing a user from a group) far more reliable than hunting for stray user-attached policies.

## How Checkov evaluates this
This is a graph check (`IAMUsersAreMembersAtLeastOneGroup.json`), not attribute-based Python logic. It filters resources of type `aws_iam_group_membership` and requires that a connection exists between:
- the `aws_iam_group_membership` resource and an `aws_iam_user` resource, AND
- the `aws_iam_group_membership` resource and an `aws_iam_group` resource

In practice, Checkov builds a resource graph from the Terraform configuration (following the `users` and `group` arguments of `aws_iam_group_membership`, or implicit references) and fails if an `aws_iam_user` exists that is never connected to a group through such a membership resource. If no `aws_iam_group_membership` resource references a given user at all, that user has no group affiliation and the check fails for that configuration.

## Non-compliant example
```hcl
resource "aws_iam_user" "developer" {
  name = "jane.developer"
}

resource "aws_iam_user_policy_attachment" "developer_policy" {
  user       = aws_iam_user.developer.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}
# No aws_iam_group_membership resource references "jane.developer"
```

## Remediated example
```hcl
resource "aws_iam_user" "developer" {
  name = "jane.developer"
}

resource "aws_iam_group" "developers" {
  name = "developers"
}

resource "aws_iam_group_policy_attachment" "developers_policy" {
  group      = aws_iam_group.developers.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

# The added membership resource satisfies the check
resource "aws_iam_group_membership" "developer_membership" {
  name  = "developer-team-membership"
  users = [aws_iam_user.developer.name]
  group = aws_iam_group.developers.name
}
```

## Remediation steps
1. Create (or reuse) an `aws_iam_group` that represents the user's job function or team.
2. Attach IAM policies to that group instead of to individual users.
3. Add an `aws_iam_group_membership` resource (or `aws_iam_user_group_membership`, which Checkov's graph model also generally recognizes as establishing the group relationship) that lists the user(s) requiring that access.
4. Remove any direct `aws_iam_user_policy_attachment` / `aws_iam_policy_attachment` resources tied straight to the user, migrating those permissions to the group.
5. Note: `aws_iam_group_membership` fully replaces the membership list each time it is applied for the named group membership resource — if you manage memberships for the same group from multiple Terraform resources you can get drift; prefer one canonical membership resource (or `aws_iam_user_group_membership` per user) per group to avoid clobbering.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/IAMUsersAreMembersAtLeastOneGroup.json)
- [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
