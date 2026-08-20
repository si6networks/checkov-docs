# CKV_GCP_102: Ensure that GCP Cloud Run services are not anonymously or publicly accessible

## Severity
**HIGH** (score: 7.5/10)

Granting allUsers/allAuthenticatedUsers IAM access to a Cloud Run service can expose internal or sensitive application functionality directly to unauthenticated internet traffic.

## Summary
This check ensures that IAM bindings/members applied to a Cloud Run service do not grant invocation access to the public principals `allUsers` or `allAuthenticatedUsers`.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework**: Terraform
- **Resource types**: `google_cloud_run_service_iam_member`, `google_cloud_run_service_iam_binding`

## Why it matters
Cloud Run services frequently back internal APIs, webhooks, or backend microservices that assume requests come only from trusted callers (other services, an authenticated gateway, or specific principals). Granting `roles/run.invoker` to `allUsers`:

- **Makes the service invocable by literally anyone on the internet** with no authentication, bypassing whatever authorization logic exists (or doesn't exist) inside the application itself — many internal services are not written defensively because they were never meant to receive untrusted traffic.
- **Exposes it to abuse and cost attacks**: Since Cloud Run bills per-request/CPU-time, an unauthenticated, publicly invokable endpoint can be hit by scanners or bots, driving up cost and potentially triggering downstream rate limits or denial of service against dependent systems.
- **`allAuthenticatedUsers`** grants invocation to any entity holding *any* Google identity token, not just members of your organization — a common misunderstanding that results in far broader exposure than intended (e.g., any external Gmail user can obtain a valid Google ID token and invoke the service).
- **Chained exploitation**: If the Cloud Run service has permissions to call other GCP APIs (via its runtime service account) or access internal data stores, an attacker who can invoke it unauthenticated may be able to trigger unintended downstream actions.

## How Checkov evaluates this
The check (`GCPCloudRunPrivateService`) branches on resource type:
- For **`google_cloud_run_service_iam_member`**: reads the `member` attribute; **FAILS** if it is `"allUsers"` or `"allAuthenticatedUsers"`.
- For **`google_cloud_run_service_iam_binding`**: reads the `members` list; **FAILS** if either public principal is present.
- Otherwise **PASSES**.

## Non-compliant example
```hcl
resource "google_cloud_run_service_iam_member" "public_invoker" {
  service  = google_cloud_run_service.api.name
  location = google_cloud_run_service.api.location
  project  = "my-project"
  role     = "roles/run.invoker"
  member   = "allUsers"
}
```

## Remediated example
```hcl
resource "google_cloud_run_service_iam_member" "gateway_invoker" {
  service  = google_cloud_run_service.api.name
  location = google_cloud_run_service.api.location
  project  = "my-project"
  role     = "roles/run.invoker"
  member   = "serviceAccount:api-gateway@my-project.iam.gserviceaccount.com"
}
```

## Remediation steps
1. Remove any `google_cloud_run_service_iam_member`/`_iam_binding` resource that grants `roles/run.invoker` (or other roles) to `allUsers`/`allAuthenticatedUsers`.
2. Grant invocation rights to specific service accounts (e.g., an API gateway, Cloud Scheduler, Pub/Sub push subscription's service account, or another Cloud Run service's runtime identity).
3. Where a service genuinely needs to be public (e.g., a public-facing website), keep the public grant but pair it with application-level authentication/authorization and place it behind a WAF/API gateway (Cloud Armor, API Gateway) for rate limiting and abuse protection, and document this as an intentional exception.
4. Verify the service's runtime service account itself has least-privilege IAM permissions, so that even if invocation is compromised, downstream blast radius is limited.
5. Re-scan with Checkov and confirm via `gcloud run services get-iam-policy` that no public bindings remain outside Terraform-managed state.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GCPCloudRunPrivateService.py
- GCP Cloud Run authentication documentation: https://cloud.google.com/run/docs/authenticating/overview
