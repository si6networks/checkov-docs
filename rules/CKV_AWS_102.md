# CKV_AWS_102: Ensure Neptune Cluster instance is not publicly available
## Severity
**HIGH** (score: 8.0/10)

A publicly accessible Neptune cluster instance exposes a graph database directly to the internet, materially increasing the risk of unauthorized access to potentially sensitive data absent additional network controls.

## Summary
This check ensures that Amazon Neptune cluster instances are not configured with `publicly_accessible = true`, preventing direct internet exposure of the graph database.

## Applicability
**Checkov framework(s):** `terraform`

Terraform resource `aws_neptune_cluster_instance`, specifically the `publicly_accessible` attribute.

## Why it matters
Neptune is designed to be accessed from within a VPC by application servers; it has no built-in expectation of being reachable directly from the public internet. Setting `publicly_accessible = true` assigns a publicly resolvable DNS endpoint and, combined with a permissive security group, can expose the database's query endpoint directly to internet scanning and attack. Graph databases holding relationship/identity data (social graphs, fraud detection graphs, knowledge graphs) are high-value targets; a publicly reachable instance dramatically increases the attack surface for credential brute-forcing, exploitation of any Neptune engine vulnerabilities, and unauthorized data access, especially if paired with weak network ACLs or default credentials. Keeping database instances private and reachable only via VPC networking (VPN, peering, or bastion/application tier) is a foundational network-segmentation control.

## How Checkov evaluates this
This is a Python check built on `BaseResourceNegativeValueCheck`, which inspects the `publicly_accessible` attribute (first element of the list) and treats `True` as a forbidden value:
- If `publicly_accessible` is `true`, the check **FAILS**.
- If `publicly_accessible` is `false` or the attribute is omitted (default is not publicly accessible for Neptune), the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_neptune_cluster_instance" "graph_instance" {
  cluster_identifier    = aws_neptune_cluster.graph.id
  instance_class        = "db.r5.large"
  publicly_accessible   = true
}
```

## Remediated example
```hcl
resource "aws_neptune_cluster_instance" "graph_instance" {
  cluster_identifier    = aws_neptune_cluster.graph.id
  instance_class        = "db.r5.large"
  publicly_accessible   = false
}
```

## Remediation steps
1. Set `publicly_accessible = false` (or remove the attribute, since `false` is the default) on every `aws_neptune_cluster_instance`.
2. Ensure application/consumer access to Neptune goes through a private VPC path — same VPC, VPC peering, Transit Gateway, or PrivateLink — rather than the public internet.
3. If external access is genuinely required, front the database with an application layer / API gateway that enforces authentication and authorization, rather than exposing Neptune directly.
4. Note: changing `publicly_accessible` on an existing instance may require a reboot or brief availability interruption depending on the Neptune engine version.
5. Re-run Checkov to confirm the finding clears.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/NeptuneClusterInstancePublic.py)
- [Terraform aws_neptune_cluster_instance documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/neptune_cluster_instance)
