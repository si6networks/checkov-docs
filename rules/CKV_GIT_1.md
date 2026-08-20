# CKV_GIT_1: Ensure GitHub repository is Private
## Severity
**HIGH** (score: 7.5/10)

A repository that should be private but is left public exposes proprietary source code, configuration, and any embedded logic or secrets to the entire internet.

## Summary
This check ensures a `github_repository` Terraform resource is configured as private (or at least internal), rather than publicly visible.

## Applicability
**Checkov framework(s):** `terraform`

Applies to Terraform configurations using the `github` provider, specifically the `github_repository` resource type.

## Why it matters
A publicly visible GitHub repository exposes its entire commit history, source code, issues, and (unless carefully scrubbed) any secrets accidentally committed to anyone on the internet — including automated scrapers that continuously scan public GitHub for leaked API keys and credentials. Even code with no obvious secrets can leak business logic, internal architecture, unpatched vulnerability details, or proprietary algorithms. For organizations, an unintentionally public repository is one of the most common and severe real-world data-exposure incidents. Defaulting new repositories to private (or internal, for enterprise-scoped visibility) closes this exposure vector by default rather than relying on developers to remember to set visibility correctly.

## How Checkov evaluates this
The `PrivateRepo` check inspects the `github_repository` resource block:
- **PASS** if `private = true`, OR
- **PASS** if `visibility` is set to `"private"` or `"internal"`.
- **FAIL** in every other case (including when neither attribute is set, since the provider/GitHub default for new repos is public unless overridden).

Both `private` and `visibility` are evaluated because the GitHub Terraform provider supports either attribute (visibility is the newer, more expressive field that also supports `internal` for GitHub Enterprise).

## Non-compliant example
```hcl
resource "github_repository" "app" {
  name        = "payments-service"
  description = "Payments processing service"
  # no "private" or "visibility" set -> defaults to public
}
```

## Remediated example
```hcl
resource "github_repository" "app" {
  name        = "payments-service"
  description = "Payments processing service"
  visibility  = "private"   # fix: explicitly private (or "internal" for org-wide visibility)
}
```

## Remediation steps
1. Add `private = true` or `visibility = "private"` (or `"internal"` if the repo should be visible org-wide but not to the public) to every `github_repository` resource.
2. If a repository must legitimately be public (e.g., open-source project), explicitly set `visibility = "public"` and suppress this check for that resource with a Checkov skip comment (`#checkov:skip=CKV_GIT_1:<reason>`), so the exception is intentional and auditable.
3. For existing public repos being locked down, review the `Settings > General > Danger Zone > Change repository visibility` implications — switching to private can break integrations that assumed public access (e.g., some CI, package registry, or GitHub Pages configurations) and existing forks are unaffected but new forking/cloning access changes immediately.
4. Combine with org-level policy: GitHub Enterprise organizations can enforce default repository visibility centrally so this is not solely reliant on per-resource Terraform correctness.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/github/PrivateRepo.py)
- [Terraform GitHub provider: github_repository](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/repository)
