# CKV_AWS_386: Reduce potential for WhoAMI cloud image name confusion attack

## Severity
**LOW** (score: 2.0/10)

An unrestricted 'owners' filter on an aws_ami data source enables the whoAMI name-confusion supply-chain attack, letting an attacker publish a malicious public AMI that gets selected instead of the legitimate image, resulting in full compromise of every instance launched from it.

## Summary
This check ensures a Terraform `aws_ami` data source that filters AMIs by name specifies a trusted `owners` list, since relying only on a permissive name-pattern filter (e.g., containing wildcards) without an owner restriction is vulnerable to the "whoAMI" name-confusion supply-chain attack.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_ami` (data source)

## Why it matters
The "whoAMI" attack (publicly disclosed in 2025) exploits the fact that `aws_ami` data source lookups by name, when not restricted to specific trusted `owners`, will match **any publicly shared AMI** whose name satisfies the filter pattern — regardless of who published it. An attacker can:

1. Publish a malicious public AMI whose name is crafted to match a common wildcard pattern used internally (e.g., `my-company-base-image-*`).
2. Wait for automation (Terraform, Packer, Auto Scaling launch templates using `most_recent = true`) to pick up the newest AMI matching that name filter — which, without an `owners` restriction, could resolve to the attacker's AMI instead of the legitimate internal one.
3. Achieve full compromise of every EC2 instance launched from the resulting AMI, since the attacker controls its entire boot image (backdoors, credential harvesters, etc.).

This is a supply-chain attack: nothing in the Terraform config appears "wrong" at a glance (it's a normal `filter` block), but the missing `owners` restriction means the trust boundary is implicitly "any AWS account that publishes a public AMI," not "my own organization."

## How Checkov evaluates this
The check inspects the `aws_ami` data source configuration:

1. If `owners` is specified and non-empty, the check **PASSES** immediately (the account trust boundary is explicit).
2. If `owners` is empty/absent, it looks at the `filter` blocks for one where `name` equals `"name"` (i.e., a filter on the AMI's Name field) and inspects its `values`.
3. If any of those name-filter values contain a wildcard character (`*` or `?`), the check **FAILS** — an unrestricted, ownerless wildcard name match is exactly the whoAMI attack surface.
4. Otherwise (no wildcard in the name filter, or no name filter present), the check **PASSES**.

## Non-compliant example
```hcl
data "aws_ami" "example" {
  most_recent = true

  filter {
    name   = "name"
    values = ["my-company-base-image-*"]
  }
}
```

## Remediated example
```hcl
data "aws_ami" "example" {
  most_recent = true
  owners      = ["123456789012"]  # your own account ID, or a trusted publisher's account ID

  filter {
    name   = "name"
    values = ["my-company-base-image-*"]
  }
}
```

## Remediation steps
1. Always set `owners` on every `aws_ami` data source, scoped to your own account ID, a specific trusted third-party publisher account ID (e.g., a known vendor's account), or the well-known alias `"amazon"`/`"self"` where appropriate — never leave it unset when using name-based filters.
2. Avoid `owners = ["*"]` or omitting `owners`, since that reopens the same trust gap.
3. Where possible, prefer pinning to a specific AMI ID (via a data source keyed on `image-id` filter, or an SSM Parameter Store AMI reference from a trusted parameter path) rather than a "most recent by name" pattern, to remove ambiguity entirely.
4. Audit existing Packer/Terraform pipelines and Auto Scaling launch templates for any AMI lookups lacking `owners`, since this is a retroactive supply-chain risk, not just a net-new one.
5. This is a data-source query change only; it does not affect running infrastructure until the next `apply`/AMI refresh, but verify the correct AMI still resolves after adding the `owners` restriction.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/data/aws/WhoAMI.py)
- [AWS AMI data source documentation (Terraform Registry)](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami)
