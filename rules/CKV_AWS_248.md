# CKV_AWS_248: Ensure that Elasticsearch is not using the default Security Group

## Severity
**LOW** (score: 2.0/10)

An Elasticsearch/OpenSearch domain left without an explicit security group falls back to the account's default SG, which is often broadly permissive and can expose a data-bearing search cluster to unintended network access.

## Summary
This check ensures that an Elasticsearch/OpenSearch domain deployed inside a VPC has an explicit, dedicated security group assigned rather than falling back to the VPC's default security group.

## Applicability
- **Framework:** Terraform
- **Resource types:** `aws_elasticsearch_domain`, `aws_opensearch_domain`

## Why it matters
The default security group of a VPC is created automatically and, by default, allows all traffic between resources that reference it — teams frequently leave it wide open or attach it to many unrelated resources over time, making it a shared, uncontrolled trust boundary. If an Elasticsearch/OpenSearch domain uses the default SG (because `vpc_options.security_group_ids` was left unset), it inherits whatever broad access rules that group has accumulated, and any other resource placed in the default SG gains network access to the search cluster. Since Elasticsearch domains frequently have no additional authentication in front of their transport/REST APIs beyond network-layer controls, an overly permissive or shared security group can mean any compromised instance in the VPC can query, modify, or exfiltrate the entire index — this has been the root cause of several public Elasticsearch data breaches at other organizations.

## How Checkov evaluates this
The check inspects:

```
vpc_options/[0]/security_group_ids
```

with an expected value of `ANY_VALUE`.

- **PASS**: `vpc_options { security_group_ids = [...] }` contains at least one explicit security group ID.
- **FAIL**: `vpc_options` is absent, or `security_group_ids` is not set — meaning AWS will attach the account's default security group for that VPC.

## Non-compliant example
```hcl
resource "aws_elasticsearch_domain" "example" {
  domain_name = "example-logs"

  vpc_options {
    subnet_ids = [aws_subnet.a.id, aws_subnet.b.id]
    # security_group_ids not set -> falls back to default VPC security group
  }
}
```

## Remediated example
```hcl
resource "aws_security_group" "es_sg" {
  name        = "es-domain-sg"
  description = "Dedicated SG for Elasticsearch domain"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

resource "aws_elasticsearch_domain" "example" {
  domain_name = "example-logs"

  vpc_options {
    subnet_ids         = [aws_subnet.a.id, aws_subnet.b.id]
    security_group_ids = [aws_security_group.es_sg.id]   # <-- added
  }
}
```

## Remediation steps
1. Create a dedicated security group scoped only to the traffic the search domain actually needs (e.g., HTTPS/9200 from application security groups only).
2. Set `vpc_options.security_group_ids` on the domain resource to that group's ID — never rely on the implicit default.
3. Audit the account's default security group separately and ensure it has no permissive rules, as a defense-in-depth measure (some organizations enforce a policy that the default SG allows nothing).
4. Note: changing `security_group_ids` on an existing domain is typically an in-place update, but validate with `terraform plan` since VPC-related domain changes can sometimes require a blue/green domain migration depending on other simultaneous changes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ElasticsearchDefaultSG.py)
- [Terraform: aws_elasticsearch_domain vpc_options](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain)
- [AWS: VPC support for Amazon OpenSearch Service domains](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html)
