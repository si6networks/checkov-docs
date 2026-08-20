# CKV2_AWS_16: Ensure that Auto Scaling is enabled on your DynamoDB tables

## Severity
**LOW** (score: 2.0/10)

Lacking Auto Scaling on DynamoDB tables is primarily an availability and cost-management concern rather than a security exposure.

## Summary
This check ensures that DynamoDB tables using provisioned billing mode have Application Auto Scaling configured (or use on-demand `PAY_PER_REQUEST` billing instead) so read/write capacity scales automatically with load.

## Applicability
Terraform (AWS provider). Applies to `aws_dynamodb_table` resources, evaluated in connection with `aws_appautoscaling_target`/`aws_appautoscaling_policy` resources.

## Why it matters
A DynamoDB table on `PROVISIONED` billing mode with fixed, statically-set read/write capacity units will throttle requests once traffic exceeds the provisioned capacity, returning `ProvisionedThroughputExceededException` errors to clients. This is primarily an availability/reliability concern: under a traffic spike (a marketing campaign, a retry storm from an upstream failure, or even a DDoS-adjacent burst), a table without auto scaling will simply start rejecting requests rather than scaling to absorb the load, potentially cascading into application-wide outages. Conversely, static over-provisioning to avoid throttling wastes money continuously. Auto scaling (or the fully-managed `PAY_PER_REQUEST` mode) keeps capacity aligned with actual demand automatically.

## How Checkov evaluates this
This is a graph-based (JSON) policy that **PASSES** if either branch is true for an `aws_dynamodb_table`:
1. **Provisioned + autoscaled branch**: the table is connected to an `aws_appautoscaling_target`, which is in turn connected to an `aws_appautoscaling_policy`; the table's `billing_mode` is either `"PROVISIONED"` or unset (provisioned is the Terraform-level default); and the `aws_appautoscaling_target.service_namespace` equals `"dynamodb"`. **OR**
2. **On-demand branch**: the table's `billing_mode` equals `"PAY_PER_REQUEST"` (in which case AWS manages capacity automatically and no explicit auto scaling config is needed).

If the table is on `PROVISIONED` mode (or `billing_mode` is unset) and has no connected `aws_appautoscaling_target`/`policy` for DynamoDB, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_dynamodb_table" "orders" {
  name           = "orders"
  billing_mode   = "PROVISIONED"
  hash_key       = "order_id"
  read_capacity  = 5
  write_capacity = 5

  attribute {
    name = "order_id"
    type = "S"
  }
  # No aws_appautoscaling_target / policy configured for this table
}
```

## Remediated example
```hcl
resource "aws_dynamodb_table" "orders" {
  name           = "orders"
  billing_mode   = "PROVISIONED"
  hash_key       = "order_id"
  read_capacity  = 5
  write_capacity = 5

  attribute {
    name = "order_id"
    type = "S"
  }
}

resource "aws_appautoscaling_target" "orders_read" {           # <-- fixed
  max_capacity       = 50
  min_capacity       = 5
  resource_id        = "table/${aws_dynamodb_table.orders.name}"
  scalable_dimension  = "dynamodb:table:ReadCapacityUnits"
  service_namespace   = "dynamodb"
}

resource "aws_appautoscaling_policy" "orders_read_policy" {    # <-- fixed
  name               = "orders-read-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.orders_read.resource_id
  scalable_dimension = aws_appautoscaling_target.orders_read.scalable_dimension
  service_namespace  = aws_appautoscaling_target.orders_read.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }
    target_value = 70
  }
}

# (Repeat aws_appautoscaling_target/policy for WriteCapacityUnits,
#  or alternatively set billing_mode = "PAY_PER_REQUEST" and remove
#  read_capacity/write_capacity/autoscaling resources entirely.)
```

## Remediation steps
1. For tables using `PROVISIONED` billing mode, add `aws_appautoscaling_target` resources for both `ReadCapacityUnits` and `WriteCapacityUnits` scalable dimensions.
2. Add a matching `aws_appautoscaling_policy` (typically `TargetTrackingScaling`) for each target, tuned to a target utilization (commonly 70%).
3. Alternatively, switch `billing_mode` to `"PAY_PER_REQUEST"` and remove `read_capacity`/`write_capacity` — simpler, fully-managed, and often more cost-effective for unpredictable or spiky workloads (though potentially costlier at sustained high, steady throughput).
4. Set `min_capacity`/`max_capacity` bounds that reflect realistic traffic ranges and cost tolerance — auto scaling reacts on a delay (minutes), so extremely spiky "surge" traffic may still benefit from on-demand mode or provisioned capacity with burst headroom.
5. Apply the same treatment to any Global Secondary Indexes on the table, which have their own read/write capacity and scaling targets.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/AutoScalingEnableOnDynamoDBTables.json
