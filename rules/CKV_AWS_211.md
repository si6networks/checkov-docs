# CKV_AWS_211: Ensure RDS uses a modern CaCert
## Severity
**LOW** (score: 2.0/10)

An outdated RDS CA certificate can break or weaken TLS certificate validation for database connections as older root CAs are deprecated, increasing exposure to man-in-the-middle risk on data in transit.

## Summary
This check ensures that an `aws_db_instance` resource specifies a modern RDS certificate authority (CA) certificate for encrypting client-to-database connections, rather than relying on an older/deprecated CA.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_db_instance`

## Why it matters
RDS instances present a TLS certificate signed by an AWS-managed CA to clients that connect over SSL/TLS. AWS periodically rotates and deprecates its CA bundles (e.g. the original `rds-ca-2015`/`rds-ca-2019` certificates were scheduled for expiration). If an instance is pinned to (or defaults to) an old CA, two risks arise: (1) once the old CA certificate expires, clients that verify the certificate chain will fail to connect, causing an availability incident; and (2) older CA certificates use weaker signing algorithms (e.g. SHA-1 based chains in some legacy bundles) that are more susceptible to certificate-forgery attacks, weakening the guarantee that clients are actually talking to the genuine RDS endpoint rather than a man-in-the-middle. Using a current CA (RSA2048, RSA4096, or ECC384 generation-1 certificates) ensures long certificate validity and stronger cryptography.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the `ca_cert_identifier` attribute of `aws_db_instance`:
- If `ca_cert_identifier` is **absent**, the check explicitly **PASSES** (`missing_block_result=CheckResult.PASSED`) — Checkov assumes the AWS default CA is acceptable/unknown-but-not-flagged in this case.
- If `ca_cert_identifier` is present, its value must be one of the expected modern values: `rds-ca-rsa2048-g1`, `rds-ca-rsa4096-g1`, or `rds-ca-ecc384-g1`.
- Any other explicit value (e.g. `rds-ca-2019`) causes the check to **FAIL**.

## Non-compliant example
```hcl
resource "aws_db_instance" "example" {
  identifier           = "example-db"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.medium"
  allocated_storage    = 20
  username             = "admin"
  password             = "changeme123!"
  ca_cert_identifier   = "rds-ca-2019"
  skip_final_snapshot  = true
}
```

## Remediated example
```hcl
resource "aws_db_instance" "example" {
  identifier           = "example-db"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.medium"
  allocated_storage    = 20
  username             = "admin"
  password             = "changeme123!"
  ca_cert_identifier   = "rds-ca-rsa2048-g1"
  skip_final_snapshot  = true
}
```

## Remediation steps
1. Set `ca_cert_identifier` on the `aws_db_instance` resource to one of the current-generation values: `rds-ca-rsa2048-g1` (default/broadly compatible), `rds-ca-rsa4096-g1` (stronger key), or `rds-ca-ecc384-g1` (elliptic-curve, smaller/faster handshakes but requires client driver support).
2. Verify your database client/driver supports the chosen CA family before switching, especially for `ecc384`, which is not supported by all legacy drivers.
3. Apply the change with Terraform — note that changing `ca_cert_identifier` triggers a reboot of the RDS instance to install the new certificate, causing a brief connection interruption; schedule during a maintenance window.
4. Update any client-side trust store / CA bundle used for certificate verification (`sslrootcert` for Postgres, `rds-combined-ca-bundle.pem` for others) to include the new CA before or immediately after the cutover to avoid connection failures.
5. Re-run Checkov to confirm the resource passes.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/RDSCACertIsRecent.py)
- [AWS RDS: Using SSL/TLS to encrypt a connection (rotating your CA certificate)](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL-certificate-rotation.html)
