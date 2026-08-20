# CKV_GCP_107: Cloud functions should not be public

## Severity
**HIGH** (score: 7.5/10)

Public IAM bindings on a Cloud Function can expose serverless application logic, and any data or backend systems it touches, to unauthenticated invocation from the internet.

## Summary
This check ensures that IAM bindings/members applied to a Google Cloud Function (1st or 2nd generation) do not grant invocation access to the public principal `allUsers`.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework**: Terraform
- **Resource types**: `google_cloudfunctions_function_iam_member`, `google_cloudfunctions_function_iam_binding` (1st gen), `google_cloudfunctions2_function_iam_member`, `google_cloudfunctions2_function_iam_binding` (2nd gen)

## Why it matters
The flagged examples in this repository (BigQuery data-loading functions such as `jira-bq-cloud-function`, `influx-to-bigquery`, and `auth0-bq-cloud-function`) are exactly the kind of internal, data-pipeline functions that should never be reachable by unauthenticated internet traffic:

- **Unauthenticated invocation of data pipelines**: Granting `allUsers` invocation rights on functions like these means any unauthenticated party on the internet can trigger the function to run — potentially re-triggering expensive BigQuery loads, corrupting or duplicating data, or probing the function's behavior/error messages for information disclosure (e.g., stack traces revealing internal service names, table schemas, or credentials handling logic).
- **Cost and denial-of-service exposure**: Cloud Functions bill per invocation/compute-time; a public function is a target for automated scanners and can be repeatedly invoked to run up cost or exhaust downstream quota (e.g., BigQuery load job limits).
- **Credential/service-account risk**: These functions likely run with a service account permitted to write to BigQuery; if the function itself has any exploitable flaw (e.g., accepts unsanitized input that affects the destination table or query), unauthenticated public invocation removes the only barrier (the need to be an authorized caller) protecting that write path.
- **Function-specific data exposure**: A function pulling from Jira, InfluxDB, or Auth0 into BigQuery likely handles internal system data or identity data; even successful, "intended" output triggered by an unauthorized caller could leak information about internal system state through response payloads, logs, or side effects.

## How Checkov evaluates this
The check (`CloudFunctionsShouldNotBePublic`) inspects the config for both the singular and plural member forms, across both 1st- and 2nd-gen resource types:
- If `member` is present as a list, **FAILS** if `member == ["allUsers"]`; otherwise **PASSES**.
- If `members` is present and its first element is a list, **FAILS** if `"allUsers"` is found in that list; otherwise **PASSES**.
- If neither `member` nor `members` matches these shapes, the result is `UNKNOWN` (Checkov cannot determine compliance from static configuration alone, e.g., if the value comes from a variable it can't resolve).
- Note that only `allUsers` is checked here (unlike some sibling checks that also flag `allAuthenticatedUsers`).

## Non-compliant example
```hcl
resource "google_cloudfunctions_function_iam_member" "invoker_allusers" {
  project        = "my-project"
  region         = "us-central1"
  cloud_function = google_cloudfunctions_function.jira_bq_sync.name
  role           = "roles/cloudfunctions.invoker"
  member         = "allUsers"
}
```

## Remediated example
```hcl
resource "google_cloudfunctions_function_iam_member" "invoker_scheduler" {
  project        = "my-project"
  region         = "us-central1"
  cloud_function = google_cloudfunctions_function.jira_bq_sync.name
  role           = "roles/cloudfunctions.invoker"
  member         = "serviceAccount:cloud-scheduler-invoker@my-project.iam.gserviceaccount.com"
}
```

## Remediation steps
1. In each affected module (`jira-bq-cloud-function`, `influx-to-bigquery`, `auth0-bq-cloud-function`), locate the `*_iam_member`/`*_iam_binding` resource granting `allUsers` invocation and replace `member`/`members` with a specific service account identity.
2. For scheduled/triggered functions, use the invoking service's dedicated identity: e.g., the Cloud Scheduler job's service account, the Pub/Sub push subscription's service account, or an Eventarc trigger's service account for 2nd-gen functions.
3. If the function must be triggered by an external webhook (e.g., Auth0), prefer using a shared-secret/HMAC signature verification inside the function combined with a narrowly scoped invoker identity (such as a dedicated service account used only by an API Gateway that validates the webhook signature) rather than making the endpoint itself public.
4. Re-run `terraform plan`/`apply` and verify with `gcloud functions get-iam-policy` (or `gcloud functions2`) that `allUsers` no longer appears in the bindings.
5. Re-scan with Checkov; if the check reports `UNKNOWN` because `member`/`members` is set via a variable, manually verify the resolved value doesn't end up being `allUsers` in any environment (dev/staging/prod tfvars).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/CloudFunctionsShouldNotBePublic.py
- GCP Cloud Functions IAM documentation: https://cloud.google.com/functions/docs/securing/managing-access-iam
