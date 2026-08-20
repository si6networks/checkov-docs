# CKV_AWS_242: Ensure MWAA environment has scheduler logs enabled

## Severity
**LOW** (score: 2.0/10)

Missing scheduler logs remove visibility into DAG parsing and scheduling behavior, delaying detection of malicious or unauthorized DAG activity in an environment where DAGs are executable code, though this is a monitoring gap rather than a direct exposure.

## Summary
This check ensures that an Amazon Managed Workflows for Apache Airflow (MWAA) environment has scheduler logging enabled, so scheduler activity is captured in CloudWatch Logs.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_mwaa_environment`

## Why it matters
The Airflow scheduler is the component responsible for parsing DAGs, deciding when tasks run, and triggering task execution — it is central to both the correctness and the security posture of an MWAA environment. Without scheduler logs enabled, operators lose visibility into scheduling decisions, DAG parsing errors, and any anomalous scheduling behavior (e.g. unexpected DAG triggers, unauthorized DAG modifications being picked up and executed, or a compromised DAG file causing unusual task-execution patterns). This blind spot has real security and incident-response consequences: if an attacker manages to inject or modify a DAG (a documented risk in shared or loosely-permissioned Airflow environments, since DAGs are executable Python code), scheduler logs are often the first place unusual activity would surface — repeated failures, unexpected DAG registrations, or scheduling loops. Disabling this logging also removes an audit trail needed for troubleshooting pipeline failures and for compliance requirements around operational logging of data-processing systems.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects `logging_configuration[0].scheduler_logs[0].enabled` on the `aws_mwaa_environment` resource.
- **PASS** if this nested attribute is explicitly set to `true`.
- **FAIL** if the `logging_configuration`/`scheduler_logs` block is absent, or `enabled` is missing/`false`.
- Note: unlike some checks in this batch, this one has no `missing_block_result` override, so an entirely absent `logging_configuration` block results in a **FAIL** (not an automatic pass).

## Non-compliant example
```hcl
resource "aws_mwaa_environment" "airflow" {
  name              = "data-pipelines"
  execution_role_arn = aws_iam_role.mwaa.arn
  source_bucket_arn  = aws_s3_bucket.dags.arn
  dag_s3_path        = "dags/"

  network_configuration {
    security_group_ids = [aws_security_group.mwaa.id]
    subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  }
}
```

## Remediated example
```hcl
resource "aws_mwaa_environment" "airflow" {
  name              = "data-pipelines"
  execution_role_arn = aws_iam_role.mwaa.arn
  source_bucket_arn  = aws_s3_bucket.dags.arn
  dag_s3_path        = "dags/"

  logging_configuration {
    scheduler_logs {
      enabled  = true
      log_level = "INFO"
    }
  }

  network_configuration {
    security_group_ids = [aws_security_group.mwaa.id]
    subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  }
}
```

## Remediation steps
1. Add a `logging_configuration` block to the `aws_mwaa_environment` resource with a nested `scheduler_logs` block setting `enabled = true`.
2. Choose an appropriate `log_level` (e.g. `INFO` or `WARNING`) balancing log verbosity/cost against the detail needed for investigations.
3. Consider enabling the other MWAA log types in the same block (`dag_processing_logs`, `task_logs`, `webserver_logs`, `worker_logs`) for full observability coverage, since each is configured independently.
4. Set a CloudWatch Logs retention policy and, if required, forward these logs to a centralized SIEM/log-aggregation pipeline for correlation with other security telemetry.
5. This is an in-place configuration update in AWS and does not require replacing the MWAA environment, though MWAA environment updates can take a nontrivial amount of time to apply.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/MWAASchedulerLogsEnabled.py)
- [Amazon MWAA: Viewing Airflow logs](https://docs.aws.amazon.com/mwaa/latest/userguide/what-is-mwaa.html)
