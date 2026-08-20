# CKV_AWS_243: Ensure MWAA environment has worker logs enabled

## Severity
**LOW** (score: 2.0/10)

Missing MWAA worker log shipping removes the only durable record of task execution on ephemeral workers, degrading incident-response and anomaly-detection capability rather than creating a direct exploit path.

## Summary
This check ensures that an AWS Managed Workflows for Apache Airflow (MWAA) environment is configured to publish worker task logs to CloudWatch Logs.

## Applicability
**Checkov framework(s):** `terraform`

- **Framework:** Terraform
- **Resource type:** `aws_mwaa_environment`

## Why it matters
Airflow worker logs contain the stdout/stderr of every task instance run by your DAGs — including tracebacks, custom logging statements, and often diagnostic output about the data being processed. Without worker log shipping enabled, this information is only available on the (ephemeral, managed) Airflow workers and is lost once a worker is recycled, which happens routinely in MWAA's autoscaling model. That leaves you unable to perform post-incident forensics when a task fails or misbehaves, unable to detect anomalous execution patterns (e.g. a compromised DAG making unexpected outbound calls), and unable to meet audit/compliance requirements that mandate retention of execution logs for data pipelines. Because MWAA environments frequently orchestrate sensitive ETL jobs touching production data stores, losing this log trail directly weakens incident response and change-attribution capability.

## How Checkov evaluates this
The check is a `BaseResourceValueCheck` that inspects the nested attribute path:

```
logging_configuration/[0]/worker_logs/[0]/enabled
```

- **PASS**: `logging_configuration { worker_logs { enabled = true } }` is set.
- **FAIL**: the `worker_logs` block is absent, or `enabled` is `false`/unset.

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

  # No logging_configuration block at all -> worker_logs disabled
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
      enabled   = true          # <-- added
      log_level = "INFO"
    }
  }
}
```

## Remediation steps
1. Add a `logging_configuration` block to the `aws_mwaa_environment` resource if one doesn't exist.
2. Within it, add a `worker_logs { enabled = true }` sub-block; set `log_level` to `INFO` or `WARNING` depending on verbosity needs.
3. While making this change, also consider enabling `dag_processing_logs`, `scheduler_logs`, `task_logs`, and `webserver_logs` for full pipeline observability (see CKV_AWS_244 for webserver logs).
4. Apply the change — this is a non-destructive, in-place update in most cases but confirm with `terraform plan` since some MWAA attribute changes can force environment recreation.
5. Route the resulting CloudWatch log group to your central logging/SIEM pipeline and set an appropriate retention policy.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MWAAWorkerLogsEnabled.py)
- [AWS MWAA — Viewing Airflow logs](https://docs.aws.amazon.com/mwaa/latest/userguide/log-types.html)
