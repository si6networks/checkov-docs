# CKV_TC_13: Ensure Tencent Cloud CVM user data does not contain sensitive information

## Severity
**CRITICAL** (score: 8.5/10)

Embedding Tencent Cloud API secret ID/key directly in instance user data exposes account-level credentials to any process or user with local instance or metadata-service access, enabling privilege escalation well beyond the instance itself.

## Summary
This check ensures that the user-data / cloud-init payload of a Tencent Cloud CVM instance does not embed Tencent Cloud API secret ID/key credentials in plaintext.

## Applicability
**Checkov framework(s):** `terraform`

Terraform, resource type `tencentcloud_instance` (Tencent Cloud provider), specifically the `user_data` and `user_data_raw` attributes.

## Why it matters
Instance user data (cloud-init scripts) is commonly readable by any process or user on the instance via the local metadata service, and is often also visible to anyone with read access to the Terraform state file, plan output, or the CI/CD pipeline that applied the configuration — none of which require compromising the instance itself. Embedding `TENCENTCLOUD_SECRET_ID`/`TENCENTCLOUD_SECRET_KEY` directly in user data means that any process running on the instance (including a compromised application, a malicious container, or any user with local shell access) can retrieve these account-level API credentials and use them to call the Tencent Cloud API with whatever privileges are attached to that key — potentially far exceeding what the instance itself needs. This is a specific instance of the general anti-pattern of embedding long-lived cloud credentials in instance bootstrap data rather than using instance-scoped roles/CAM policies or a secrets manager.

## How Checkov evaluates this
This is a `BaseResourceCheck` that inspects the `user_data_raw` and `user_data` attributes of a `tencentcloud_instance` for the literal substrings `"TENCENTCLOUD_SECRET_ID"` or `"TENCENTCLOUD_SECRET_KEY"`. If either substring appears in either attribute's value, the check **FAILS**. If neither substring is present in either attribute (or both are unset), the check **PASSES**.

## Non-compliant example
```hcl
resource "tencentcloud_instance" "example" {
  instance_name = "worker"
  image_id      = "img-9qabwvbn"
  instance_type = "S5.MEDIUM4"

  user_data = base64encode(<<-EOF
    #!/bin/bash
    export TENCENTCLOUD_SECRET_ID="AKIDxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    export TENCENTCLOUD_SECRET_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    /opt/app/start.sh
  EOF
  )
}
```

## Remediated example
```hcl
resource "tencentcloud_instance" "example" {
  instance_name = "worker"
  image_id      = "img-9qabwvbn"
  instance_type = "S5.MEDIUM4"
  cam_role_name = "worker-instance-role"   # CAM role grants scoped API access instead

  user_data = base64encode(<<-EOF
    #!/bin/bash
    /opt/app/start.sh   # app fetches credentials from the CAM role / metadata service at runtime
  EOF
  )
}
```

## Remediation steps
1. Remove any `TENCENTCLOUD_SECRET_ID` / `TENCENTCLOUD_SECRET_KEY` values from `user_data`/`user_data_raw`.
2. Attach a Tencent Cloud CAM (Cloud Access Management) role to the instance (`cam_role_name`) so applications on the instance obtain temporary, automatically-rotated credentials from the metadata service instead of static long-lived keys.
3. Scope the CAM role's policy to the minimum permissions the instance's workload actually needs.
4. If a CAM role cannot cover the use case, retrieve secrets at boot time from a secrets manager over an authenticated channel, rather than embedding them directly in the bootstrap script.
5. Rotate any secret ID/key that was previously embedded in user data, since instance metadata and Terraform state/plan history may retain the old value.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/CVMUserData.py
