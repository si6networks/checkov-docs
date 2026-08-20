# CKV_AWS_127: Ensure that Elastic Load Balancer(s) uses SSL certificates provided by AWS Certificate Manager

## Severity
**HIGH** (score: 7.5/10)

An ELB without an ACM-issued TLS certificate can leave traffic unencrypted or relying on self-managed/expired certificates, exposing data in transit to interception or making the endpoint vulnerable to trust-validation failures.

## Summary
This check requires that every listener on a "classic" Elastic Load Balancer (`aws_elb`) specify an SSL certificate (`ssl_certificate_id`), ensuring encrypted, certificate-backed listeners rather than plaintext or unauthenticated endpoints.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform (AWS provider)
- **Resource type:** `aws_elb` (Classic Load Balancer)

## Why it matters
A load-balancer listener without an SSL certificate is either serving plaintext traffic (e.g., HTTP or raw TCP) or terminating TLS without a properly managed, trusted certificate. Traffic sent to such a listener can be intercepted, tampered with, or downgraded by an on-path attacker, exposing credentials, session tokens, and sensitive payloads in transit. Using AWS Certificate Manager (ACM)-issued certificates additionally ensures certificates are automatically rotated/renewed, avoiding expiry-driven outages, and avoids operators manually handling private key material.

## How Checkov evaluates this
The check (`BaseResourceCheck.scan_resource_conf`) iterates over every `listener` block defined in the `aws_elb` resource:
- For each listener, it checks whether the key `ssl_certificate_id` is present.
- **FAIL** as soon as any listener block is missing `ssl_certificate_id`.
- **PASS** only if every listener in the resource includes `ssl_certificate_id`.
- If there is no `listener` block at all, the loop is skipped and it defaults to **PASS** (Checkov cannot infer that a load balancer has no listeners in practice — but per the code, an ELB with zero listener blocks passes vacuously).

Note: the check only verifies the *presence* of `ssl_certificate_id`, not whether it actually references a valid or ACM-issued ARN.

## Non-compliant example
```hcl
resource "aws_elb" "classic" {
  name               = "legacy-app-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 443
    lb_protocol       = "https"
    # ssl_certificate_id missing -> FAIL
  }
}
```

## Remediated example
```hcl
resource "aws_acm_certificate" "app" {
  domain_name       = "app.example.com"
  validation_method = "DNS"
}

resource "aws_elb" "classic" {
  name               = "legacy-app-elb"
  availability_zones = ["us-east-1a", "us-east-1b"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 443
    lb_protocol       = "https"
    ssl_certificate_id = aws_acm_certificate.app.arn   # added
  }
}
```

## Remediation steps
1. Issue or import a certificate in AWS Certificate Manager (`aws_acm_certificate`), and validate it (DNS or email validation).
2. Add `ssl_certificate_id = aws_acm_certificate.<name>.arn` to every `listener` block on the `aws_elb` resource.
3. Ensure the listener's `lb_protocol` is `HTTPS` or `SSL` — attaching a certificate to a plain `HTTP`/`TCP` listener is not meaningful and AWS will reject it.
4. Consider migrating from the legacy Classic Load Balancer (`aws_elb`) to an Application Load Balancer (`aws_lb`), which is the AWS-recommended modern option and covered by separate, more granular Checkov checks (e.g., CKV_AWS_131 for header handling).
5. This change can typically be applied without replacing the ELB resource, but modifying listener ports/protocols may cause a brief listener reconfiguration.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ELBUsesSSL.py)
- [AWS: Listeners for your Classic Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-listener-config.html)
