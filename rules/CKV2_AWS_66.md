# CKV2_AWS_66: Ensure MWAA environment is not publicly accessible

## Severity
**HIGH** (score: 7.5/10)

A publicly accessible MWAA (managed Airflow) webserver exposes a powerful workflow-orchestration UI/API — capable of executing arbitrary DAG code and reaching connected credentials — to the internet, a broad exposure of a sensitive management interface.

## Summary
This check requires Amazon Managed Workflows for Apache Airflow (MWAA) environments to either omit `webserver_access_mode` (which defaults to private) or explicitly set it to `PRIVATE_ONLY`, preventing the Airflow web UI from being reachable over the public internet.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `aws_mwaa_environment`

## Why it matters
The Airflow web UI exposes DAG source, connection metadata, task logs, and — critically — a code-execution surface: Airflow's UI and API allow triggering DAG runs, and many DAGs execute arbitrary Python/shell code with the permissions of the Airflow execution role (which often has broad access to data stores, secrets, and other AWS resources for orchestration purposes). If the webserver is `PUBLIC_ONLY`, this UI is reachable directly from the internet, at which point any authentication weakness (default credentials, missing MFA, session fixation, an unpatched Airflow CVE) becomes a direct path to executing arbitrary orchestrated workflows against production data infrastructure. Airflow logs and connection details visible through the UI can also leak credentials or infrastructure topology to unauthenticated observers if authentication is ever misconfigured. Keeping the environment `PRIVATE_ONLY` (VPC-internal, reachable only via VPN/Direct Connect/bastion) removes this exposure entirely, requiring network-level access as a precondition to reaching the UI/API at all.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy) with an `or` of two passing conditions on `aws_mwaa_environment`:
1. `webserver_access_mode` **does not exist** (Terraform/AWS default is `PRIVATE_ONLY`, so omission is safe).
2. `webserver_access_mode` **equals** `"PRIVATE_ONLY"` explicitly.

If `webserver_access_mode` is explicitly set to `PUBLIC_ONLY`, neither condition holds and the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_mwaa_environment" "data_pipelines" {
  name              = "prod-data-pipelines"
  airflow_version   = "2.7.2"
  execution_role_arn = aws_iam_role.mwaa_execution.arn
  source_bucket_arn = aws_s3_bucket.mwaa_dags.arn
  dag_s3_path       = "dags/"

  network_configuration {
    security_group_ids = [aws_security_group.mwaa.id]
    subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  }

  webserver_access_mode = "PUBLIC_ONLY"   # exposes Airflow UI to the internet -> FAILS
}
```

## Remediated example
```hcl
resource "aws_mwaa_environment" "data_pipelines" {
  name              = "prod-data-pipelines"
  airflow_version   = "2.7.2"
  execution_role_arn = aws_iam_role.mwaa_execution.arn
  source_bucket_arn = aws_s3_bucket.mwaa_dags.arn
  dag_s3_path       = "dags/"

  network_configuration {
    security_group_ids = [aws_security_group.mwaa.id]
    subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  }

  webserver_access_mode = "PRIVATE_ONLY"  # changed: internal access only
}
```

## Remediation steps
1. Set `webserver_access_mode = "PRIVATE_ONLY"` (or remove the attribute entirely to take the private default).
2. Ensure users can still reach the environment via VPN, AWS Client VPN, Direct Connect, or a bastion/jump host into the VPC — plan connectivity before flipping this on for an environment currently reachable publicly.
3. Note that changing `webserver_access_mode` on an existing MWAA environment triggers an update that can take significant time (MWAA environment updates are not instantaneous) and may briefly interrupt webserver access — schedule during a maintenance window.
4. Pair this with tightly scoped security groups on the `network_configuration` block so that even VPC-internal reachability is limited to expected source ranges.
5. Independently review the Airflow execution role's IAM permissions (`execution_role_arn`) since network isolation doesn't limit what an authenticated Airflow user/DAG can do once inside.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/AWS_private_MWAA_environment.json
- AWS docs: https://docs.aws.amazon.com/mwaa/latest/userguide/configuring-networking.html
