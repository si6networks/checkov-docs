# CKV_GCP_101: Ensure that Artifact Registry repositories are not anonymously or publicly accessible

## Severity
**HIGH** (score: 7.5/10)

A publicly accessible Artifact Registry repository can leak proprietary container images and source artifacts, and undermines trust in the software supply chain for anything built from those images.

## Summary
This check ensures that IAM bindings/members applied to a Google Artifact Registry repository do not grant access to the public principals `allUsers` or `allAuthenticatedUsers`.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework**: Terraform
- **Resource types**: `google_artifact_registry_repository_iam_member`, `google_artifact_registry_repository_iam_binding`

## Why it matters
Artifact Registry repositories typically store container images, language packages (npm, Maven, Python), and other build artifacts that may embed proprietary source code, secrets accidentally baked into images, or internal business logic. Granting `allUsers` or `allAuthenticatedUsers` read/write access creates serious risks:

- **Intellectual property and secrets leakage**: A publicly readable repository lets anyone pull your container images or packages, potentially exposing proprietary code, embedded configuration, or credentials mistakenly committed into image layers.
- **Supply-chain tampering**: If a public grant includes write-capable roles (e.g., `roles/artifactregistry.writer` or `repoAdmin`), any authenticated Google identity worldwide could push a malicious image or package version into your registry, which downstream CI/CD or production systems might then pull and run trusting it as your own artifact.
- **`allAuthenticatedUsers` is broader than it sounds**: Teams sometimes intend this for "authenticated users in our org" but it actually applies to any Google account holder globally, dramatically expanding the exposure beyond what was intended.
- **Registry as an attack pivot**: A compromised or poisoned image in a build/deploy pipeline is a classic path to full CI/CD and production compromise, so registry write access is especially sensitive.

## How Checkov evaluates this
The check (`ArtifactRegistryPrivateRepo`) branches on resource type:
- For **`google_artifact_registry_repository_iam_member`**: reads the `member` attribute; **FAILS** if it is `"allUsers"` or `"allAuthenticatedUsers"`.
- For **`google_artifact_registry_repository_iam_binding`**: reads the `members` list; **FAILS** if either public principal appears in that list.
- Otherwise **PASSES**.

## Non-compliant example
```hcl
resource "google_artifact_registry_repository_iam_member" "public_pull" {
  project    = "my-project"
  location   = "us-central1"
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = "allUsers"
}
```

## Remediated example
```hcl
resource "google_artifact_registry_repository_iam_member" "ci_pull" {
  project    = "my-project"
  location   = "us-central1"
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:ci-deployer@my-project.iam.gserviceaccount.com"
}
```

## Remediation steps
1. Locate any `google_artifact_registry_repository_iam_member`/`_iam_binding` resource granting access to `allUsers` or `allAuthenticatedUsers` and remove it.
2. Grant access instead to specific service accounts (for CI/CD pull/push) or groups/users, scoped to the least-privilege role needed (`reader` for pulling, `writer` only for pipelines that must publish).
3. If a repository is genuinely meant to serve public open-source images/packages, treat that as a deliberate, reviewed decision — isolate it in its own project/repository so the exposure boundary is explicit and doesn't risk leaking into private artifact repos through shared IAM policy.
4. Check for broader project-level `artifactregistry.reader`/`writer` grants that could implicitly make the repository public even if this specific resource looks fine.
5. Re-scan with Checkov after remediation and audit via `gcloud artifacts repositories get-iam-policy` to confirm no lingering public bindings applied outside of Terraform.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/ArtifactRegistryPrivateRepo.py
- GCP Artifact Registry access control documentation: https://cloud.google.com/artifact-registry/docs/access-control
