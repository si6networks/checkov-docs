# CKV_AWS_137: Ensure that Elasticsearch is configured inside a VPC

## Severity
**CRITICAL** (score: 9.0/10)

An Elasticsearch/OpenSearch domain deployed outside a VPC gets a public network endpoint, a well-known root cause of large-scale data breaches when combined with weak or misconfigured access policies.

## Summary
This check requires Elasticsearch/OpenSearch domains to set a `vpc_options` block, placing the domain's network endpoint inside a VPC rather than exposing it on the public internet-facing endpoint.

## Applicability
- **Framework:** Terraform (AWS provider)
- **Resource types:** `aws_elasticsearch_domain`, `aws_opensearch_domain`

## Why it matters
An Elasticsearch/OpenSearch domain deployed without `vpc_options` gets a public endpoint reachable from the internet, relying entirely on the domain's access policy (IAM/resource-based policy) and, if configured, fine-grained access control to keep it secure. Elasticsearch clusters are a frequent target for opportunistic scanning and attack precisely because misconfigured public domains (open access policies, no authentication) have repeatedly led to large-scale data breaches — attackers scan for exposed Elasticsearch/Kibana endpoints and, if access controls are weak or misconfigured, can read, exfiltrate, or destroy indexed data (which often includes logs, PII, or application data). Placing the domain inside a VPC removes the public network path entirely, so access is restricted to hosts within the VPC (or connected via VPN/peering/Transit Gateway), providing defense-in-depth even if the resource/access policy is misconfigured.

## How Checkov evaluates this
The check (`ElasticsearchInVPC`, `BaseResourceValueCheck`) uses `ANY_VALUE` as the expected value for `vpc_options`:
- **PASS** if the `vpc_options` block/attribute is present with any value (i.e., any VPC configuration at all).
- **FAIL** if `vpc_options` is absent (domain uses the public endpoint).

The check does not validate which subnets/security groups are used inside `vpc_options` — only that the block exists.

## Non-compliant example
```hcl
resource "aws_elasticsearch_domain" "logs" {
  domain_name           = "app-logs"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "r6g.large.elasticsearch"
  }
  # vpc_options not set -> public endpoint -> FAIL
}
```

## Remediated example
```hcl
resource "aws_elasticsearch_domain" "logs" {
  domain_name           = "app-logs"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "r6g.large.elasticsearch"
  }

  vpc_options {                                   # added
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_group_ids = [aws_security_group.es.id]
  }
}
```

## Remediation steps
1. Add a `vpc_options` block referencing private subnet(s) and a dedicated security group scoped to only the ports/sources that legitimately need access (typically 443 from application/bastion hosts).
2. Ensure the chosen subnets have sufficient available IP addresses and, for multi-AZ deployments, span the same AZs used by `cluster_config.zone_awareness_config`.
3. **Important:** moving an existing public domain into a VPC (or vice versa) requires the domain to be recreated — this is a destructive, in-place-incompatible change; plan a migration (snapshot/restore or reindex to a new VPC-based domain) rather than expecting a zero-downtime `terraform apply`.
4. Combine with a restrictive domain access policy and (for OpenSearch) fine-grained access control / IAM authentication as defense-in-depth, rather than relying on VPC placement alone.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticsearchInVPC.py)
- [AWS: Launching your Amazon OpenSearch Service domains within a VPC](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html)
