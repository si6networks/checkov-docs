# CKV2_AWS_39: Ensure DNS query logging is enabled for Amazon Route 53 hosted zones
## Severity
**LOW** (score: 2.0/10)

Missing DNS query logging removes visibility into potentially malicious or anomalous DNS resolution activity, a detective-control gap rather than a direct exposure of data or access.

## Summary
This check ensures that Route 53 public hosted zones have DNS query logging enabled via a connected `aws_route53_query_log` resource, so that queries against the zone are recorded.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource types:** `aws_route53_zone` (connected `aws_route53_query_log`)
- **Category:** Logging

## Why it matters
DNS query logs record which names were queried against your hosted zone, from where, and how often. Without this logging, you have no visibility into reconnaissance activity against your domain (e.g., an attacker enumerating subdomains looking for forgotten/staging endpoints), no way to detect DNS-based data exfiltration (a technique where compromised internal systems tunnel stolen data out encoded in DNS queries to attacker-controlled subdomains), and no forensic record to correlate with other logs (VPC Flow Logs, CloudTrail, WAF logs) during an incident investigation. Query logs are also useful operationally — spotting spikes in queries for a particular record can flag both attacks and misconfigured clients. Because DNS is often the first, unauthenticated protocol touched in an attack chain, having a durable log of what was queried closes an otherwise-common blind spot in security monitoring.

## How Checkov evaluates this
This is a graph check (`Route53ZoneHasMatchingQueryLog.json`) with two PASS branches combined via `or`:
1. The `aws_route53_zone`'s `vpc` attribute exists (i.e., it's a **private** hosted zone) → PASS, since query logging via `aws_route53_query_log` applies to public zones; private zone query visibility is typically handled via VPC-level DNS query logging (Resolver query logging) instead, which this check does not evaluate.
2. The zone is filtered as `aws_route53_zone` AND a graph connection exists from it to an `aws_route53_query_log` resource → PASS.

So a public hosted zone (no `vpc` attribute) with no connected `aws_route53_query_log` resource fails this check.

## Non-compliant example
```hcl
resource "aws_route53_zone" "public" {
  name = "example.com"
}
# No aws_route53_query_log configured
```

## Remediated example
```hcl
resource "aws_route53_zone" "public" {
  name = "example.com"
}

resource "aws_cloudwatch_log_group" "dns_query_logs" {
  # Log group must be created in us-east-1 for Route 53 query logging
  provider          = aws.us_east_1
  name              = "/aws/route53/example.com"
  retention_in_days = 90
}

resource "aws_route53_query_log" "public_query_log" {
  zone_id                  = aws_route53_zone.public.zone_id
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.dns_query_logs.arn
}
```

## Remediation steps
1. Create a CloudWatch Logs log group **in the `us-east-1` region** — Route 53 query logging requires the destination log group to be in `us-east-1` regardless of where your zone or account's default region is.
2. Attach a resource policy to the log group permitting the Route 53 service principal (`route53.amazonaws.com`) to write log events to it.
3. Create an `aws_route53_query_log` resource referencing the zone's `zone_id` and the log group's ARN.
4. Set an appropriate retention period on the log group, balancing investigative/audit needs against storage cost, given DNS query volume can be high for popular domains.
5. Route logs to a SIEM or alerting pipeline if you want active detection (e.g., alerting on queries for known malicious/tunneling-pattern subdomains) rather than passive log retention alone.
6. For private hosted zones, use VPC Resolver query logging (`aws_route53_resolver_query_log_config`) instead, since this check and `aws_route53_query_log` apply to public zone query logging specifically.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/Route53ZoneHasMatchingQueryLog.json)
- [AWS Route 53 query logging documentation](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html)
