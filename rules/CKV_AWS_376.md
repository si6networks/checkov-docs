# CKV_AWS_376: Ensure AWS Elastic Load Balancer listener uses TLS/SSL

## Severity
**HIGH** (score: 7.5/10)

An ELB listener using plaintext HTTP/TCP (or HTTPS without a certificate) leaves data in transit unencrypted, exposing traffic to interception and manipulation by anyone positioned on the network path.

## Summary
This check ensures that a classic Elastic Load Balancer (`aws_elb`) listener does not use unencrypted `HTTP`/`TCP` as its instance protocol, and that when it does use `HTTPS`/`SSL`, a valid SSL certificate is actually attached.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_elb` (classic Elastic Load Balancer)

## Why it matters
Traffic between the load balancer and backend instances (or between client and ELB, depending on which listener leg is being evaluated) that uses plain `HTTP` or `TCP` is transmitted unencrypted. This exposes:

- Session tokens, cookies, credentials, and any sensitive payload to interception by anyone with visibility into the network path (e.g., a compromised host on the same VPC, a misconfigured routing rule, or an on-path attacker in a shared/multi-tenant environment).
- Data integrity — unencrypted TCP/HTTP traffic can be tampered with in transit without detection.

Even when `HTTPS`/`SSL` is nominally configured as the protocol, forgetting to attach `ssl_certificate_id` means the listener cannot actually perform TLS termination correctly, which is also flagged as a failure since the configuration is incomplete/inconsistent.

## How Checkov evaluates this
For each `listener` block in the `aws_elb` resource, the check reads `instance_protocol`:

- If `instance_protocol` is `http` or `tcp` (case-insensitive) → **FAIL** immediately (unencrypted protocol).
- If `instance_protocol` is `https` or `ssl` (case-insensitive) → the check additionally requires `ssl_certificate_id` to be present and non-empty. If it's missing or an empty string → **FAIL**.
- Otherwise (no matching listener protocol found, or all listeners pass the above conditions) → **PASS**.

## Non-compliant example
```hcl
resource "aws_elb" "example" {
  name               = "example-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
}
```

## Remediated example
```hcl
resource "aws_elb" "example" {
  name               = "example-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port      = 443
    instance_protocol  = "https"
    lb_port            = 443
    lb_protocol        = "https"
    ssl_certificate_id = aws_acm_certificate.example.arn
  }
}
```

## Remediation steps
1. Change each listener's `instance_protocol` (and typically `lb_protocol`) from `http`/`tcp` to `https`/`ssl`.
2. Attach a valid `ssl_certificate_id`, referencing either an ACM certificate ARN or an IAM server certificate ARN.
3. Update the corresponding port (commonly 443) to match.
4. Consider migrating off the classic ELB entirely to an Application Load Balancer (`aws_lb`/`aws_alb`) or Network Load Balancer with a TLS listener, since classic ELB is a legacy resource with fewer security features (see also CKV_AWS_378 for target-group protocol checks on the newer ELBv2 resources).
5. No resource replacement is required for a protocol change on an existing classic ELB listener, but expect a brief connection drain/reconfiguration window during apply.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ELBwListenerNotTLSSSL.py)
- [AWS Classic Load Balancer listener configuration](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-listener-config.html)
