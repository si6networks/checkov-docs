# CKV_GCP_117: Ensure basic roles are not used at project level.

## Severity
**HIGH** (score: 7.5/10)

Basic roles at the project level (Owner/Editor) grant sweeping, unscoped permissions over every resource in the project instead of the specific permissions actually needed.

## Summary
This check fails when a `google_project_iam_member` or `google_project_iam_binding` resource assigns a legacy GCP basic role (`roles/owner`, `roles/editor`, `roles/viewer`) at the project level, since these roles grant sweeping, poorly-scoped permissions across the entire project.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `google_project_iam_member`, `google_project_iam_binding`
- **Check type:** resource

## Why it matters
Basic roles at the project level are the most common form of over-privileging in GCP because they are the "default" roles many engineers reach for:
- `roles/owner` grants full control of the project, including the ability to modify IAM bindings, delete resources, and manage billing.
- `roles/editor` grants create/modify/delete access to nearly every resource type in the project (compute, storage, networking, databases, etc.) without the ability to manage IAM — but is still extremely broad.
- `roles/viewer` grants read access to nearly all resource metadata and configuration project-wide, which can expose secret names, network architecture, and other information useful for further attacks even without direct data access.

Because these roles bundle together permissions across every GCP service in the project, granting them to a service account or human user means that a compromise of that single identity (leaked key, phished credentials, SSRF into metadata server, etc.) gives an attacker broad lateral access across the whole project rather than being contained to the specific resource(s) that identity actually needed to touch.

## How Checkov evaluates this
The check (`GoogleProjectBasicRoles`, via the shared `AbsGoogleBasicRoles` base class) inspects the resource's `role` attribute:
- It reads the first element of the `role` list.
- If the role equals `roles/owner`, `roles/editor`, or `roles/viewer`, the check returns **FAILED**.
- Any other predefined or custom role returns **PASSED**.
- The evaluated key is `role`.

## Non-compliant example
```hcl
resource "google_project_iam_binding" "delivery_platform_project_iam_binding" {
  project = "my-gcp-project"
  role    = "roles/editor"

  members = [
    "serviceAccount:delivery-platform@my-gcp-project.iam.gserviceaccount.com",
  ]
}
```

## Remediated example
```hcl
resource "google_project_iam_binding" "delivery_platform_project_iam_binding" {
  project = "my-gcp-project"
  role    = "roles/pubsub.publisher"  # narrowly scoped to the permissions actually needed

  members = [
    "serviceAccount:delivery-platform@my-gcp-project.iam.gserviceaccount.com",
  ]
}
```

## Remediation steps
1. For each flagged binding, identify exactly which GCP APIs/actions the service account or user actually invokes (check application code, or use IAM Recommender / Policy Analyzer for real usage data).
2. Replace `roles/owner`/`roles/editor`/`roles/viewer` with the smallest set of predefined roles that covers that usage (e.g. `roles/storage.objectAdmin`, `roles/pubsub.publisher`, `roles/cloudsql.client`), or define a custom role.
3. If multiple distinct permission sets are needed, use multiple narrow `google_project_iam_member` grants rather than one broad binding — this also makes future audits and diffs clearer.
4. Apply the change, then verify the workload still functions correctly against the narrower role (test in a non-production project first).
5. Use GCP's [IAM Recommender](https://cloud.google.com/iam/docs/recommender-overview) to find existing basic-role grants across your GCP projects that aren't yet captured in Terraform.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/GoogleProjectBasicRole.py)
- [GCP basic and predefined roles](https://cloud.google.com/iam/docs/understanding-roles)
