# CKV2_GCP_10: Ensure GCP Cloud Function HTTP trigger is secured
## Severity
**HIGH** (score: 7.0/10)

An HTTP-triggered Cloud Function without https_trigger_security_level=SECURE_ALWAYS can accept unencrypted or downgraded connections on a publicly reachable serverless endpoint, exposing invocation payloads and any embedded credentials to network interception.

## Summary
This check ensures that any Cloud Function using an HTTP trigger requires authenticated (secure) invocations by setting `https_trigger_security_level` to `SECURE_ALWAYS`, rather than allowing unauthenticated/insecure HTTP access.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform, specifically the `google_cloudfunctions_function` resource (Cloud Functions 1st gen HTTP-triggered functions).

## Why it matters
An HTTP-triggered Cloud Function is invoked over a plain public URL. If it doesn't enforce `SECURE_ALWAYS` for `https_trigger_security_level`, the function can be reached over unencrypted HTTP in addition to HTTPS, meaning request/response data (potentially including secrets, tokens, or sensitive payloads) could traverse the network in plaintext and be intercepted or tampered with by a network-position attacker. Beyond transport security, HTTP-triggered functions are also frequently left with no IAM invoker restriction, so an insecure or unauthenticated trigger effectively exposes an unauthenticated, internet-reachable API endpoint that anyone can invoke — a common source of resource-exhaustion abuse (running up billing costs), data exfiltration if the function touches sensitive backends, or use as a pivot point into other GCP services the function's service account can reach.

## How Checkov evaluates this
An `or` of two `attribute` conditions on `google_cloudfunctions_function` — PASS if either holds:
1. `trigger_http != true` — the function isn't HTTP-triggered at all (e.g. it's event/Pub/Sub-triggered), so this check doesn't apply.
2. `https_trigger_security_level == "SECURE_ALWAYS"` — the function explicitly requires HTTPS-only, secure invocation.

FAIL only when `trigger_http == true` and `https_trigger_security_level` is anything other than `"SECURE_ALWAYS"` (including left unset).

## Non-compliant example
```hcl
resource "google_cloudfunctions_function" "webhook" {
  name        = "webhook-handler"
  runtime     = "python312"
  entry_point = "handle_request"

  trigger_http = true
  # https_trigger_security_level not set -> defaults to allowing insecure HTTP
}
```

## Remediated example
```hcl
resource "google_cloudfunctions_function" "webhook" {
  name        = "webhook-handler"
  runtime     = "python312"
  entry_point = "handle_request"

  trigger_http               = true
  https_trigger_security_level = "SECURE_ALWAYS"
}
```

## Remediation steps
1. For every `google_cloudfunctions_function` with `trigger_http = true`, explicitly set `https_trigger_security_level = "SECURE_ALWAYS"`.
2. Additionally restrict invocation with IAM: avoid `allUsers`/`allAuthenticatedUsers` on the function's Cloud Run/Cloud Functions invoker binding; grant `roles/cloudfunctions.invoker` only to specific service accounts or identities that need it.
3. If migrating to Cloud Functions 2nd gen (backed by Cloud Run), use Cloud Run's ingress controls and IAM invoker policies for equivalent (or stronger) protection — note the attribute name/behavior differs for `google_cloudfunctions2_function`.
4. Re-run Checkov and confirm the finding clears for the three affected files listed above.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/CloudFunctionSecureHTTPTrigger.json
- GCP docs: https://cloud.google.com/functions/docs/securing/authenticating
