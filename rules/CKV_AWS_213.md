# CKV_AWS_213: Ensure ELB Policy uses only secure protocols
## Severity
**LOW** (score: 2.0/10)

Allowing SSLv3/TLS 1.0/1.1 (or an outdated ELB security policy) on a load balancer exposes client traffic to known protocol downgrade and cipher weaknesses (e.g. POODLE/BEAST), enabling interception or tampering with in-transit data for internet-facing services.

## Summary
This check ensures that a Classic Elastic Load Balancer (ELB) SSL negotiation policy (`aws_load_balancer_policy`) does not enable deprecated/insecure SSL/TLS protocols or reference an outdated predefined security policy.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_load_balancer_policy`

## Why it matters
Classic Load Balancers negotiate the TLS protocol and cipher suite used with clients based on the SSL negotiation policy attached to them. Protocols like SSLv3 and TLS 1.0/1.1 have known cryptographic weaknesses (e.g. POODLE against SSLv3, BEAST and weak cipher support against TLS 1.0) and are disallowed or strongly discouraged by modern compliance standards (PCI-DSS 3.2+ mandates disabling TLS below 1.2). If a load balancer policy explicitly enables `Protocol-SSLv3`, `Protocol-TLSv1`, or `Protocol-TLSv1.1`, it allows clients (including attackers performing protocol-downgrade attacks) to negotiate a weak, exploitable protocol version for the connection, potentially exposing traffic to decryption or tampering. Similarly, several of AWS's predefined `Reference-Security-Policy` bundles (e.g. `ELBSecurityPolicy-2014-01`, `-2015-05`, `-Default`) include these legacy protocols/ciphers for broad backward compatibility, so selecting one of them re-introduces the same weakness even without explicitly toggling individual protocol flags.

## How Checkov evaluates this
The check iterates over each `policy_attribute` block in the `aws_load_balancer_policy` resource:
- For attributes whose `name` is `Protocol-SSLv3`, `Protocol-TLSv1`, or `Protocol-TLSv1.1`: if the attribute's `value` is truthy (i.e. the insecure protocol is enabled), the check **FAILS** immediately.
- For an attribute named `Reference-Security-Policy`: if its `value` is one of the legacy predefined policies — `ELBSecurityPolicy-2016-08`, `ELBSecurityPolicy-TLS-1-1-2017-01`, `ELBSecurityPolicy-2015-05`, `ELBSecurityPolicy-2015-03`, `ELBSecurityPolicy-2015-02`, `ELBSecurityPolicy-TLS-1-0-2015-04`, `ELBSecurityPolicy-2014-10`, `ELBSecurityPolicy-Default`, or `ELBSecurityPolicy-2014-01` — the check **FAILS**.
- If none of the attributes trigger a failure condition, the check **PASSES**.

## Non-compliant example
```hcl
resource "aws_load_balancer_policy" "example" {
  load_balancer_name = aws_elb.example.name
  policy_name         = "example-tls-policy"
  policy_type_name    = "SSLNegotiationPolicyType"

  policy_attribute {
    name  = "Reference-Security-Policy"
    value = "ELBSecurityPolicy-2015-05"
  }
}
```

## Remediated example
```hcl
resource "aws_load_balancer_policy" "example" {
  load_balancer_name = aws_elb.example.name
  policy_name         = "example-tls-policy"
  policy_type_name    = "SSLNegotiationPolicyType"

  policy_attribute {
    name  = "Reference-Security-Policy"
    value = "ELBSecurityPolicy-TLS-1-2-2017-01"
  }
}
```

## Remediation steps
1. Remove any `policy_attribute` blocks that explicitly enable `Protocol-SSLv3`, `Protocol-TLSv1`, or `Protocol-TLSv1.1` (set their `value` to `false`, or delete them entirely if the predefined policy already excludes them).
2. If using `Reference-Security-Policy`, switch to a modern predefined policy such as `ELBSecurityPolicy-TLS-1-2-2017-01` or `ELBSecurityPolicy-FS-1-2-Res-2020-10` (forward-secrecy variant), which exclude SSLv3/TLS1.0/1.1.
3. Consider migrating from Classic Load Balancer to an Application Load Balancer (ALB) or Network Load Balancer (NLB), which use `aws_lb_listener` with a simpler `ssl_policy` argument and receive AWS's newer TLS policy updates first.
4. Test client compatibility after tightening the policy — very old clients that only support TLS 1.0/1.1 will no longer be able to connect.
5. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/ELBPolicyUsesSecureProtocols.py)
- [AWS Classic Load Balancer: Predefined SSL security policies](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html)
