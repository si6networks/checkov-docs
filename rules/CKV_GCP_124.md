# CKV_GCP_124: Ensure GCP Cloud Function is not configured with overly permissive Ingress setting

## Severity
**HIGH** (score: 7.6/10)

An overly permissive ingress setting on a Cloud Function allows invocation from outside the VPC/internal network, exposing potentially sensitive serverless application logic and its downstream permissions to the public internet.

## Summary
This check fails when a `google_cloudfunctions_function` or `google_cloudfunctions2_function` allows unrestricted ingress (i.e. its ingress setting is not one of `ALLOW_INTERNAL_ONLY` or `ALLOW_INTERNAL_AND_GCLB`), meaning the function can be invoked directly from the public internet.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `google_cloudfunctions_function` (1st gen), `google_cloudfunctions2_function` (2nd gen)
- **Check type:** resource (value check)

## Why it matters
Cloud Functions with the default ingress setting (`ALLOW_ALL`) can be triggered by any HTTP request from anywhere on the internet, subject only to whatever IAM/authentication is configured on the function's invoker permission. This creates several risks:
- If the function is also misconfigured to allow unauthenticated invocation, it becomes fully public and can be abused for scanning, DoS/cost-amplification (Cloud Functions bill per invocation/compute time), or as an entry point to internal systems the function talks to (databases, internal APIs, other GCP services).
- Even with IAM invoker restrictions in place, allowing all ingress increases the attack surface exposed to internet scanners and removes a network-layer defense-in-depth control — relying solely on application-layer IAM checks.
- Restricting ingress to `ALLOW_INTERNAL_ONLY` (VPC-internal traffic and Cloud Functions in the same project) or `ALLOW_INTERNAL_AND_GCLB` (adds traffic routed through an internal or external Application Load Balancer) confines the network paths that can reach the function at all, meaningfully shrinking what an external attacker can even attempt to exploit.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` with a resource-type-dependent inspected key:
- For `google_cloudfunctions_function` (1st gen): inspects the `ingress_settings` attribute.
- For `google_cloudfunctions2_function` (2nd gen): inspects the nested `service_config/[0]/ingress_settings/[0]` attribute.
- **Expected values:** `["ALLOW_INTERNAL_AND_GCLB", "ALLOW_INTERNAL_ONLY"]` — the check **PASSES** if the ingress setting is one of these two values.
- **FAIL** if the value is `"ALLOW_ALL"` (the GCP default) or the attribute is otherwise not one of the two accepted values.

## Non-compliant example
```hcl
resource "google_cloudfunctions2_function" "dlp_reconciliation" {
  name     = "dlp-reconciliation"
  location = "us-central1"

  build_config {
    runtime     = "python311"
    entry_point = "handle_request"
  }

  service_config {
    max_instance_count = 5
    available_memory    = "256M"
    # ingress_settings not set - defaults to ALLOW_ALL
  }
}
```

## Remediated example
```hcl
resource "google_cloudfunctions2_function" "dlp_reconciliation" {
  name     = "dlp-reconciliation"
  location = "us-central1"

  build_config {
    runtime     = "python311"
    entry_point = "handle_request"
  }

  service_config {
    max_instance_count = 5
    available_memory    = "256M"
    ingress_settings    = "ALLOW_INTERNAL_ONLY"  # <-- added
  }
}
```

## Remediation steps
1. Determine whether the function genuinely needs to be reachable from the public internet (e.g. a webhook receiver) or only from internal callers (other GCP services, VPC-internal clients, or via a load balancer).
2. If internal-only, set `ingress_settings = "ALLOW_INTERNAL_ONLY"` (1st gen: top-level attribute; 2nd gen: inside `service_config`).
3. If the function must be reachable via a load balancer (e.g. fronted by Cloud Armor / Cloud CDN), use `ALLOW_INTERNAL_AND_GCLB` instead of leaving it fully open.
4. Also review the function's IAM invoker bindings (`google_cloudfunctions_function_iam_member` / `google_cloud_run_service_iam_member` for 2nd gen) — ingress restriction and invoker authentication are complementary controls, not substitutes for each other.
5. Changing ingress settings does not typically require function recreation, but verify downstream callers (webhooks, external partners) can still reach the function through the allowed path before rolling out broadly.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/CloudFunctionPermissiveIngress.py)
- [Cloud Functions ingress settings documentation](https://cloud.google.com/functions/docs/networking/network-settings#ingress_settings)
