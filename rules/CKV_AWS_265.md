# CKV_AWS_265: Ensure Keyspaces Table uses CMK

## Severity
**LOW** (score: 2.0/10)

Keyspaces tables are encrypted at rest by an AWS-owned key even without this setting, so the risk addressed is the loss of independent key policy, rotation, and audit control over the data rather than the data being unprotected.

## Summary
This check ensures that an Amazon Keyspaces (for Apache Cassandra) table is encrypted using a customer-managed KMS key (CMK), rather than the AWS-owned default key.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: resource `aws_keyspaces_table`

## Why it matters
Amazon Keyspaces tables often hold application state and business data at scale. AWS_OWNED_KMS_KEY (the default) provides encryption at rest but is entirely managed by AWS — customers cannot view, restrict, rotate on their own schedule, or revoke access to that key. Using a CUSTOMER_MANAGED_KMS_KEY lets the organization define a precise key policy (which principals/roles may decrypt), enable independent key rotation, and get CloudTrail records of every decrypt/encrypt operation against that specific key — critical for meeting data-residency, least-privilege, and audit requirements in regulated environments. Without this, an over-permissioned IAM role that can read the table has no additional key-level access boundary standing between it and the data.

## How Checkov evaluates this
The check reads the `encryption_specification` block:
- If `encryption_specification` is missing entirely → **FAIL**.
- If present, it looks at the first element's `kms_key_identifier` and `type`.
- **PASS** only if `kms_key_identifier` is set **and** `type` is exactly `["CUSTOMER_MANAGED_KMS_KEY"]`.
- If `type` is `AWS_OWNED_KMS_KEY` (the default) or any other value, or `kms_key_identifier` is missing, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_keyspaces_table" "orders" {
  keyspace_name = aws_keyspaces_keyspace.main.name
  table_name    = "orders"

  schema_definition {
    column {
      name = "order_id"
      type = "text"
    }
    partition_key {
      name = "order_id"
    }
  }
  # no encryption_specification -> defaults to AWS_OWNED_KMS_KEY
}
```

## Remediated example
```hcl
resource "aws_keyspaces_table" "orders" {
  keyspace_name = aws_keyspaces_keyspace.main.name
  table_name    = "orders"

  schema_definition {
    column {
      name = "order_id"
      type = "text"
    }
    partition_key {
      name = "order_id"
    }
  }

  encryption_specification {
    kms_key_identifier = aws_kms_key.keyspaces.arn
    type               = "CUSTOMER_MANAGED_KMS_KEY"
  }
}
```

## Remediation steps
1. Create a dedicated customer-managed KMS key for Keyspaces, with rotation enabled.
2. Add an `encryption_specification` block with `type = "CUSTOMER_MANAGED_KMS_KEY"` and `kms_key_identifier` set to that key's ARN.
3. Update the key policy to allow the Keyspaces service and the application's execution role to use the key.
4. Caution: encryption type for an Amazon Keyspaces table is generally set at creation time; changing `encryption_specification` on an existing table typically requires recreating the table (data migration required), so plan this change during a maintenance window and script data copy/backfill as needed.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/KeyspacesTableUsesCMK.py
- AWS documentation: https://docs.aws.amazon.com/keyspaces/latest/devguide/EncryptionAtRest.html
