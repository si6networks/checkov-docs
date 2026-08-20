# CKV_TC_14: Ensure Tencent Cloud VPC flow logs are enabled

## Severity
**MEDIUM** (score: 5.0/10)

Disabled VPC flow logging removes network-traffic visibility needed to detect and investigate lateral movement or exfiltration, which degrades detection capability without itself opening an access path.

## Summary
This check ensures that Tencent Cloud VPC flow log configuration resources have flow log collection actually enabled.

## Applicability
Terraform, resource type `tencentcloud_vpc_flow_log_config` (Tencent Cloud provider).

## Why it matters
VPC flow logs record metadata about IP traffic flowing through network interfaces in a VPC — source/destination IPs and ports, protocol, byte/packet counts, and accept/reject action — without capturing packet payloads. This is one of the most valuable low-overhead data sources for network security monitoring: it enables detection of port scanning, unexpected lateral movement between subnets, communication with known-malicious IP ranges, data exfiltration via unusual outbound volume, and reconstruction of an attacker's network path during incident response. Provisioning a `tencentcloud_vpc_flow_log_config` resource but leaving it disabled (`enable = false`) gives a false sense of coverage — the configuration exists in Terraform state and code review, but no actual flow data is being collected, silently defeating the intended monitoring control.

## How Checkov evaluates this
This is a `BaseResourceNegativeValueCheck` that inspects the `enable` attribute of a `tencentcloud_vpc_flow_log_config`. `false` is the forbidden value: if `enable` is set to `false`, the check **FAILS**. If `enable` is `true` (or the provider's default results in it being enabled), the check **PASSES**.

## Non-compliant example
```hcl
resource "tencentcloud_vpc_flow_log_config" "example" {
  flow_log_name        = "vpc-flow-logs"
  vpc_id               = tencentcloud_vpc.app_vpc.id
  flow_log_storage_type = "cls"
  storage_id           = tencentcloud_clb_log_topic.example.id
  enable               = false
}
```

## Remediated example
```hcl
resource "tencentcloud_vpc_flow_log_config" "example" {
  flow_log_name         = "vpc-flow-logs"
  vpc_id                = tencentcloud_vpc.app_vpc.id
  flow_log_storage_type  = "cls"
  storage_id             = tencentcloud_clb_log_topic.example.id
  enable                 = true   # flow log collection actually active
}
```

## Remediation steps
1. Set `enable = true` on every `tencentcloud_vpc_flow_log_config` resource.
2. Confirm the referenced storage destination (`storage_id`, e.g. a CLS log topic) is correctly provisioned and has adequate retention configured.
3. Feed collected flow logs into a monitoring/alerting pipeline (traffic baselining, anomaly detection, denylist matching) rather than only collecting them passively.
4. Periodically audit that flow log configs remain enabled — a resource that exists but is disabled can pass casual code review while providing no actual security telemetry, so consider a periodic compliance check in addition to this static Terraform check.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/VPCFlowLogConfigEnable.py
