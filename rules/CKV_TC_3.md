# CKV_TC_3: Ensure Tencent Cloud CVM monitor service is enabled

## Severity
**MEDIUM** (score: 4.5/10)

Disabling the instance monitoring service reduces visibility into abnormal resource usage and availability issues, which is primarily an operational/detection gap rather than a direct path to compromise.

## Summary
This check ensures that Tencent Cloud CVM instances have the built-in cloud monitor service enabled rather than explicitly disabled.

## Applicability
Terraform, resource type `tencentcloud_instance` (Tencent Cloud provider).

## Why it matters
Cloud monitor service on CVM instances provides visibility into CPU, memory, disk, and network metrics, as well as alerting on anomalous resource usage. Without it, operators lose an early warning signal for compromise indicators such as sudden CPU spikes from cryptomining malware, unusual outbound network traffic consistent with data exfiltration or a compromised host joining a botnet, or resource exhaustion from a denial-of-service condition. Disabling monitoring does not reduce risk to the instance itself — it removes the organization's ability to detect and respond to an incident in a timely manner, extending attacker dwell time and increasing the eventual impact of any compromise.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the `disable_monitor_service` attribute of a `tencentcloud_instance` resource. `true` is the forbidden value: if `disable_monitor_service = true`, the check **FAILS**. If the attribute is absent or `false` (monitoring left enabled), the check **PASSES**.

## Non-compliant example
```hcl
resource "tencentcloud_instance" "app" {
  instance_name           = "app-server"
  availability_zone       = "ap-shanghai-2"
  image_id                = "img-9qabwvbn"
  instance_type           = "S5.MEDIUM4"
  disable_monitor_service = true
}
```

## Remediated example
```hcl
resource "tencentcloud_instance" "app" {
  instance_name           = "app-server"
  availability_zone       = "ap-shanghai-2"
  image_id                = "img-9qabwvbn"
  instance_type           = "S5.MEDIUM4"
  disable_monitor_service = false   # cloud monitor stays enabled
}
```

## Remediation steps
1. Remove `disable_monitor_service = true` or explicitly set it to `false` on every `tencentcloud_instance`.
2. Configure Tencent Cloud Monitor alarm policies for the instance (CPU, memory, disk, network thresholds) so anomalies trigger notifications.
3. Integrate monitor data with a centralized observability/SIEM pipeline if available, so instance-level anomalies feed into broader security detection.
4. If monitoring was disabled for cost reasons, evaluate whether the basic monitoring tier (typically included at no extra cost) can be left enabled instead of fully disabling it.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/CVMDisableMonitorService.py
