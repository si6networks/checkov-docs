# CKV_AWS_244: Ensure MWAA environment has webserver logs enabled

## Severity
**LOW** (score: 2.0/10)

Missing MWAA webserver log shipping removes visibility into access to the Airflow UI (a sensitive orchestration console), hampering detection of unauthorized access attempts without itself being an exploitable misconfiguration.

## Summary
This check ensures that an AWS Managed Workflows for Apache Airflow (MWAA) environment publishes its Airflow webserver logs to CloudWatch Logs.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_mwaa_environment`

## Why it matters
The Airflow webserver is the user-facing web UI that authenticates users, serves the login flow, and exposes admin actions such as triggering DAG runs, editing connections/variables, and viewing task logs. Webserver logs record HTTP access patterns, authentication attempts, and errors from that interface. Without them enabled, you lose visibility into who accessed the Airflow UI, failed login attempts (a signal of credential-stuffing or brute-force attacks), and unusual access patterns that could indicate an attacker probing an internet- or VPC-exposed Airflow console. Since MWAA environments often hold IAM roles with broad permissions to orchestrate infrastructure and data pipelines, unmonitored access to the web UI is a real path to lateral movement or unauthorized pipeline execution going undetected.

## How Checkov evaluates this
The check inspects the nested attribute path:

```
logging_configuration/[0]/webserver_logs/[0]/enabled
```

- **PASS**: `logging_configuration { webserver_logs { enabled = true } }` is present.
- **FAIL**: the `webserver_logs` block is missing, or `enabled` is `false`/unset.

## Non-compliant example
```hcl
resource "aws_mwaa_environment" "example" {
  name               = "example-airflow"
  airflow_version    = "2.6.3"
  dag_s3_path        = "dags/"
  execution_role_arn = aws_iam_role.mwaa.arn
  source_bucket_arn  = aws_s3_bucket.mwaa.arn

  network_configuration {
    security_group_ids = [aws_security_group.mwaa.id]
    subnet_ids          = [aws_subnet.a.id, aws_subnet.b.id]
  }

  logging_configuration {
    worker_logs {
      enabled = true
    }
    # webserver_logs not configured
  }
}
```

## Remediated example
```hcl
resource "aws_mwaa_environment" "example" {
  name               = "example-airflow"
  airflow_version    = "2.6.3"
  dag_s3_path        = "dags/"
  execution_role_arn = aws_iam_role.mwaa.arn
  source_bucket_arn  = aws_s3_bucket.mwaa.arn

  network_configuration {
    security_group_ids = [aws_security_group.mwaa.id]
    subnet_ids          = [aws_subnet.a.id, aws_subnet.b.id]
  }

  logging_configuration {
    worker_logs {
      enabled = true
    }
    webserver_logs {
      enabled   = true   # <-- added
      log_level = "INFO"
    }
  }
}
```

## Remediation steps
1. Add or extend the `logging_configuration` block on the `aws_mwaa_environment` resource.
2. Add a `webserver_logs { enabled = true }` sub-block with an appropriate `log_level`.
3. Combine this with CKV_AWS_243 (worker logs) and enable scheduler/DAG-processing/task logs for full coverage.
4. `terraform plan`/`apply` — verify whether this specific change is in-place or requires environment update downtime in your MWAA version.
5. Forward the CloudWatch log group to a central SIEM and configure alerting on repeated authentication failures.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MWAAWebserverLogsEnabled.py)
- [AWS MWAA — Viewing Airflow logs](https://docs.aws.amazon.com/mwaa/latest/userguide/log-types.html)
