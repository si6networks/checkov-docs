# CKV_SECRET_13: Private Key

## Severity
**MEDIUM** (score: 5.0/10)

A private key is a root-of-trust credential (SSH, TLS, or cloud service-account identity) that grants indefinite impersonation or access until explicitly revoked everywhere it is trusted, often bundled with broad IAM privileges.

## Summary
This check scans file contents for embedded PEM-format private keys (RSA, DSA, EC, OpenSSH, PGP, etc.), flagging cryptographic private key material committed directly into source, config, or credential files.

## Applicability
**Checkov framework(s):** `secrets`

- **IaC/file type**: `secrets` — Checkov's regex/entropy-based secrets scanner, applied to any scanned file (JSON credential/service-account files, `.pem`/`.key` files, Terraform, YAML, scripts, Dockerfiles, etc.), not limited to a single IaC resource type.
- **Entities**: the matched key-block string within a file; findings are reported at the file/line level.

## Why it matters
A private key is the cryptographic root of trust for whatever it authenticates — SSH access to servers, TLS termination for a service, signing for a GCP/AWS service account, or code/artifact signing. Unlike a rotatable API token, private keys are frequently tied to long-lived identity and infrastructure trust relationships (e.g., a GCP service account JSON key, as seen in this repo's example path, grants programmatic access to whatever IAM roles that service account holds). A leaked private key allows an attacker to impersonate that identity indefinitely until the key is explicitly revoked/rotated everywhere it's trusted — and because private keys are often bundled inside larger credential files (like GCP service-account JSON), a single leaked file can grant broad cloud-resource access, not just a narrow, single-purpose secret.

## How Checkov evaluates this
The secrets scanner looks for the standard PEM key-block markers — lines such as `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN PRIVATE KEY-----`, `-----BEGIN OPENSSH PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`, or `-----BEGIN PGP PRIVATE KEY BLOCK-----` — anywhere in scanned file content, including when embedded as an escaped string inside JSON (e.g., a GCP/Firebase service-account key file's `"private_key"` field). The presence of a matching BEGIN marker (with corresponding key material) is sufficient to trigger a FAIL at that file/line; there is no configuration state to evaluate — this is a pure content-pattern match.

## Non-compliant example
```json
{
  "type": "service_account",
  "project_id": "example-project",
  "private_key_id": "abc123",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7Vw3l...\n-----END PRIVATE KEY-----\n",
  "client_email": "rover-image-puller@example-project.iam.gserviceaccount.com"
}
```

## Remediated example
```json
{
  "type": "service_account",
  "project_id": "example-project",
  "_comment": "Key material removed. Fetch via secrets manager / workload identity at runtime; do not commit key files."
}
```

## Remediation steps
1. **Immediately revoke** the exposed key: for GCP service accounts, delete the specific key version in IAM & Admin → Service Accounts → Keys (do not just remove the file — the key remains valid on Google's side until explicitly deleted); for SSH keys, remove the corresponding public key from every `authorized_keys`/host it grants access to.
2. Remove the credential file/private key block from the repository entirely — service-account key files should never be committed, even to private repos.
3. Replace static key-file auth with a keyless mechanism where the platform supports it: GCP Workload Identity Federation / Workload Identity for GKE, AWS IAM roles (IRSA/instance profiles), or short-lived certificates issued by a CI/CD OIDC trust relationship.
4. If a key file is unavoidable, inject it at runtime from a secrets manager (e.g., Google Secret Manager, HashiCorp Vault) rather than storing it in the repo, and restrict file permissions on disk.
5. Purge the file from git history (`git filter-repo`/BFG) since the key material persists in every prior commit even after deletion from HEAD.
6. Audit Cloud Audit Logs / CloudTrail for the affected identity for any activity between the exposure date and the revocation.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py)
