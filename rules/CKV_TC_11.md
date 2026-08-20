# CKV_TC_11: Ensure Tencent Cloud CLB has a logging ID and topic

## Severity
**MEDIUM** (score: 4.5/10)

Missing load-balancer access logging removes a key source of visibility into reconnaissance, exploitation attempts, and incident-response reconstruction, but the absence of logs does not itself create an exploitable access path.

## Summary
This check ensures that a Tencent Cloud CLB (Cloud Load Balancer) instance is configured with both a log set ID and a log topic ID so that access logs are captured.

## Applicability
Terraform, resource type `tencentcloud_clb_instance` (Tencent Cloud provider).

## Why it matters
A load balancer sits at the network edge in front of application traffic and is often the first (and sometimes only) point that observes every inbound request, including client IPs, requested paths, response codes, and timing. Without access logging configured, security teams lose visibility into reconnaissance activity (scanning for vulnerable endpoints), exploitation attempts (SQL injection, path traversal patterns in URLs), abnormal traffic volume indicating a DDoS or credential-stuffing campaign, and cannot reconstruct the sequence of events during incident response after a breach is detected elsewhere. Access logs at the load balancer are frequently the most reliable source of truth for "who accessed what, when" precisely because they capture traffic before it reaches application-layer logging, which an attacker who has compromised the application may be able to tamper with.

## How Checkov evaluates this
This is a `BaseResourceCheck` that inspects the `log_set_id` and `log_topic_id` attributes of a `tencentcloud_clb_instance`. If either attribute is missing (`None`), the check **FAILS**. Only when both `log_set_id` and `log_topic_id` are set does the check **PASS**.

## Non-compliant example
```hcl
resource "tencentcloud_clb_instance" "example" {
  network_type = "OPEN"
  clb_name     = "public-clb"
  vpc_id       = tencentcloud_vpc.app_vpc.id
  # log_set_id / log_topic_id not configured -> no access logs captured
}
```

## Remediated example
```hcl
resource "tencentcloud_clb_instance" "example" {
  network_type  = "OPEN"
  clb_name      = "public-clb"
  vpc_id        = tencentcloud_vpc.app_vpc.id
  log_set_id    = tencentcloud_clb_log_set.clb_logs.id
  log_topic_id  = tencentcloud_clb_log_topic.clb_topic.id
}

resource "tencentcloud_clb_log_set" "clb_logs" {
  period = 30
}

resource "tencentcloud_clb_log_topic" "clb_topic" {
  log_set_id = tencentcloud_clb_log_set.clb_logs.id
  topic_name = "clb-access-logs"
}
```

## Remediation steps
1. Provision a Tencent Cloud CLS log set (`tencentcloud_clb_log_set`) and log topic (`tencentcloud_clb_log_topic`) if one does not already exist for this environment.
2. Set `log_set_id` and `log_topic_id` on the `tencentcloud_clb_instance` to reference them, so CLB access logs are shipped to CLS.
3. Set an appropriate log retention period on the log set balancing compliance/investigation needs against storage cost.
4. Wire the CLS log topic into your centralized log analysis/alerting pipeline (e.g. flag high error-rate bursts, suspicious request patterns) rather than leaving logs uncollected and unreviewed.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/tencentcloud/CLBInstanceLog.py
