# CKV2_GCP_7: Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges

## Severity
**LOW** (score: 2.0/10)

A MySQL root user without a password allows anyone who can reach the instance to authenticate with full administrative database privileges, a direct path to complete data compromise.

## Summary
This check ensures that when a Cloud SQL MySQL instance has a `google_sql_user` named `root` (or starting with `root`), that user has a password configured, rather than allowing passwordless root/administrative login.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `google_sql_database_instance`, `google_sql_user`

This is a graph-based check (Checkov "graph check", defined as JSON) that inspects the connection between a MySQL Cloud SQL instance and its associated user resources.

## Why it matters
The `root` account on a MySQL instance has full administrative privileges — it can read, modify, or delete any data, alter user grants, and disable security settings. If a `root` (or root-prefixed) database user is created without a password, anyone who can reach the database's network endpoint can authenticate as an unrestricted administrator with zero credential barrier. This is one of the most severe possible misconfigurations for a database: it converts network reachability alone into full data compromise, and is a well-known target for internet-wide scanning tools that specifically look for passwordless MySQL root accounts.

## How Checkov evaluates this
The check filters for `google_sql_database_instance` resources and passes if **any** of the following is true:
1. `database_version` does not start with `MYSQL` — the check only applies to MySQL instances (PostgreSQL/SQL Server are out of scope for this check).
2. The instance has **no connected** `google_sql_user` resource at all (e.g., users managed outside Terraform).
3. The instance **does** have a connected `google_sql_user`, and for that user: either its `name` does not start with `root`, OR (if the name does start with `root`) the user resource has a `password` attribute set.

The check **fails** specifically when a MySQL instance has a Terraform-managed user whose name starts with `root` and that user resource has no `password` attribute defined.

## Non-compliant example
```hcl
resource "google_sql_database_instance" "mysql" {
  name             = "prod-mysql"
  database_version = "MYSQL_8_0"
  region           = "us-central1"

  settings {
    tier = "db-n1-standard-1"
  }
}

resource "google_sql_user" "root" {
  name     = "root"
  instance = google_sql_database_instance.mysql.name
  # no password set - passwordless root login
}
```

## Remediated example
```hcl
resource "google_sql_database_instance" "mysql" {
  name             = "prod-mysql"
  database_version = "MYSQL_8_0"
  region           = "us-central1"

  settings {
    tier = "db-n1-standard-1"
  }
}

resource "random_password" "root" {
  length  = 24
  special = true
}

resource "google_sql_user" "root" {
  name     = "root"
  instance = google_sql_database_instance.mysql.name
  password = random_password.root.result
}
```

## Remediation steps
1. Add a `password` attribute to every `google_sql_user` resource whose `name` starts with `root`.
2. Generate strong, unique passwords (e.g., via the `random_password` Terraform resource) rather than hard-coding them in source — store the generated secret in a secret manager (e.g., Google Secret Manager) and reference it.
3. Consider avoiding the `root` account entirely for application use — create dedicated, least-privilege MySQL users per application/service.
4. Enable Cloud SQL's IAM database authentication where possible, to avoid static passwords altogether.
5. Restrict network exposure of the instance (private IP, authorized networks, or Cloud SQL Auth Proxy) as defense in depth even after fixing the password.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/gcp/DisableAccessToSqlDBInstanceForRootUsersWithoutPassword.json
- Google Cloud docs: https://cloud.google.com/sql/docs/mysql/create-manage-users
