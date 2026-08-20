# CKV_SECRET_5: Cloudant Credentials

## Severity
**LOW** (score: 2.0/10)

A detected Cloudant credential is a live, typically full read/write database credential embedded in source, and its exposure directly enables unauthorized data access, exfiltration, or destructive writes without any further exploitation step.

## Summary
This check scans plaintext files and IaC source for embedded IBM Cloudant database credentials (URLs/keys that follow the IBM Cloudant credential pattern), flagging any occurrence as a hardcoded secret.

## Applicability
**Checkov framework(s):** `secrets`

This is one of Checkov's built-in **secrets scanning** checks (framework: `secrets`), not a resource-attribute check. It runs against any text file Checkov scans as part of a repository/directory scan — source code, configuration files, IaC templates (Terraform, YAML, JSON, Dockerfiles, etc.), and plain text files — looking for the Cloudant credential pattern regardless of file type or resource type ("entities": `secrets`).

## Why it matters
Cloudant is IBM's managed database-as-a-service (built on Apache CouchDB). Its connection credentials typically embed a full HTTPS URL containing a username and API key/password (e.g. `https://<username>:<apikey>@<host>.cloudantnosqldb.appdomain.cloud`). If such a credential is committed to a git repository, CI/CD config, Terraform variable file, or Dockerfile, it becomes retrievable by anyone with read access to that repository or its history — including through forks, cached CI logs, and internal wikis where code is pasted. Because Cloudant credentials generally grant full read/write access to the database (unless IAM-scoped), a leaked credential can lead to a full data breach, mass deletion, or unauthorized writes. Once committed, the secret remains recoverable in git history even after later removal from the working tree, which is why detection at commit/scan time is critical rather than remediation after the fact.

## How Checkov evaluates this
Checkov's secrets scanning is built on the `detect-secrets` plugin framework with Checkov-specific plugins layered on top. The `CloudantDetector` plugin (registered under this check ID) applies a regular expression matching the structure of a Cloudant service credential/URL (a Cloudant hostname combined with an embedded username:password or apikey) against every line of scanned files. A match causes the plugin to flag that line as a detected secret and Checkov reports it as **FAILED** for `CKV_SECRET_5`; files/lines with no match are not flagged (there is no "pass" resource — absence of a match simply produces no finding).

## Non-compliant example
```hcl
# terraform.tfvars — Cloudant credential hardcoded as a variable default
variable "cloudant_url" {
  default = "https://admin:aB3xR9pLmN2qYzT1@examplehost-bluemix.cloudantnosqldb.appdomain.cloud"
}
```

## Remediated example
```hcl
# terraform.tfvars — no secret committed; value is injected at runtime
variable "cloudant_url" {
  description = "Cloudant service URL, supplied via TF_VAR_cloudant_url or a secrets manager"
  type        = string
  sensitive   = true
}
```
```bash
# Value is provided out-of-band, e.g.:
export TF_VAR_cloudant_url=$(vault kv get -field=url secret/cloudant)
```

## Remediation steps
1. Remove the hardcoded Cloudant URL/credential from the file and rotate the credential in IBM Cloud immediately — treat any committed secret as compromised.
2. Purge the secret from git history (e.g. `git filter-repo` or BFG Repo-Cleaner), not just the latest commit, since history remains readable.
3. Store the credential in a secrets manager (HashiCorp Vault, IBM Cloud Secrets Manager, AWS Secrets Manager) or inject it via environment variables / CI/CD masked secrets at deploy time.
4. Mark any corresponding Terraform variable `sensitive = true` so it is not echoed in plan/apply output.
5. Add a `.secrets.baseline` (via `detect-secrets scan`) and enable pre-commit hooks so future commits are checked before they reach the remote.
6. If the finding is a false positive (e.g. a test fixture with an obviously fake credential), use an inline `checkov:skip=CKV_SECRET_5` comment or an entry in the secrets baseline rather than disabling the check globally.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py
