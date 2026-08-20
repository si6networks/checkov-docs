# CKV_AWS_264: Ensure AppFlow connector profile uses CMK

## Severity
**LOW** (score: 2.0/10)

AppFlow connector profiles function as a credential store for third-party SaaS integrations, and relying on a default AWS-owned key instead of a CMK removes an independent, auditable access-control boundary over stored connection secrets.

## Summary
This check ensures that an Amazon AppFlow connector profile specifies a customer-managed KMS key ARN (`kms_arn`) so credentials and connection metadata stored by the profile are encrypted with a key the customer controls.

## Applicability
- **Terraform**: resource `aws_appflow_connector_profile`

## Why it matters
An AppFlow connector profile stores the authentication details (OAuth tokens, API keys, connection secrets) needed to connect to a third-party SaaS application such as Salesforce, Slack, or ServiceNow. This is effectively a credential store: if it is encrypted only with an AWS-owned default key, the organization cannot independently restrict, rotate, or audit who is able to decrypt those stored credentials via a key policy. If the underlying credentials are ever exposed (e.g., through a misconfigured IAM policy elsewhere in the account), the ability to decrypt them is not gated by an additional customer-controlled key boundary, removing a layer of defense-in-depth around a high-value secret.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` looking at the `kms_arn` attribute:
- **PASS**: `kms_arn` is set to any non-empty value.
- **FAIL**: `kms_arn` is absent or empty.

## Non-compliant example
```hcl
resource "aws_appflow_connector_profile" "salesforce" {
  name            = "salesforce-profile"
  connector_type  = "Salesforce"
  connection_mode = "Public"

  connector_profile_config {
    connector_profile_credentials {
      salesforce {
        client_credentials_arn = aws_secretsmanager_secret.sf_creds.arn
      }
    }
    connector_profile_properties {
      salesforce {
        instance_url = "https://mycompany.my.salesforce.com"
      }
    }
  }
  # no kms_arn set
}
```

## Remediated example
```hcl
resource "aws_appflow_connector_profile" "salesforce" {
  name            = "salesforce-profile"
  connector_type  = "Salesforce"
  connection_mode = "Public"
  kms_arn         = aws_kms_key.appflow.arn   # customer-managed key

  connector_profile_config {
    connector_profile_credentials {
      salesforce {
        client_credentials_arn = aws_secretsmanager_secret.sf_creds.arn
      }
    }
    connector_profile_properties {
      salesforce {
        instance_url = "https://mycompany.my.salesforce.com"
      }
    }
  }
}
```

## Remediation steps
1. Create (or reuse) a customer-managed KMS key for AppFlow connector profiles, with `enable_key_rotation = true`.
2. Add `kms_arn = aws_kms_key.appflow.arn` to every `aws_appflow_connector_profile` resource.
3. Grant AppFlow's service principal and any roles that need to establish the connection `kms:Decrypt`/`kms:GenerateDataKey` on the key.
4. If this key is shared across multiple connector profiles or flows, ensure its key policy is scoped narrowly enough that unrelated teams/services cannot decrypt each other's credentials.
5. Changing `kms_arn` on an existing profile may require recreating the connector profile depending on provider behavior — validate in a non-production account first.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/AppFlowConnectorProfileUsesCMK.py
- AWS documentation: https://docs.aws.amazon.com/appflow/latest/userguide/data-protection.html
