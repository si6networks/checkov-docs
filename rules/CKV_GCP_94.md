# CKV_GCP_94: Ensure Dataflow jobs are private
## Severity
**HIGH** (score: 7.0/10)

Dataflow workers configured with public IPs expose the compute nodes processing pipeline data directly to the internet, broadening the attack surface against a data-processing workload.

## Summary
This check requires `google_dataflow_job` resources to set `ip_configuration = "WORKER_IP_PRIVATE"`, so Dataflow worker VMs do not receive public IP addresses.

## Applicability
**Checkov framework(s):** `terraform`

- **IaC framework:** Terraform
- **Resource type:** `google_dataflow_job`
- **Check type:** resource (attribute-value check)

## Why it matters
Dataflow workers execute the actual data-processing pipeline code and typically carry service-account credentials with access to source/sink systems (Pub/Sub, BigQuery, Cloud Storage). Workers with public IPs are directly internet-reachable, expanding the attack surface for a compromised or vulnerable worker to be attacked from outside, or — if compromised via a supply-chain-poisoned dependency in the pipeline code — to more easily exfiltrate data outward without traversing your VPC's network controls (firewalls, Cloud NAT logging, private-access boundaries). Since Dataflow workers rarely need to be reached from the public internet (they pull work from the Dataflow service and connect outward to GCP APIs/data sources), keeping them private and routing egress through Cloud NAT/Private Google Access preserves the same network segmentation and audit trail you'd expect for any other compute processing pipeline data.

## How Checkov evaluates this
The check (`DataflowPrivateJob`, a `BaseResourceValueCheck`) inspects the `ip_configuration` attribute on `google_dataflow_job`, expecting the literal value `"WORKER_IP_PRIVATE"`.
- **PASS**: `ip_configuration = "WORKER_IP_PRIVATE"`.
- **FAIL**: `ip_configuration` is absent, or set to `"WORKER_IP_PUBLIC"` (the default).

## Non-compliant example
```hcl
resource "google_dataflow_job" "pubsub_to_bq" {
  name              = "pubsub-to-bigquery"
  template_gcs_path = "gs://dataflow-templates/latest/PubSub_to_BigQuery"
  temp_gcs_location = "gs://my-bucket/temp"
  # ip_configuration not set -> defaults to WORKER_IP_PUBLIC
}
```

## Remediated example
```hcl
resource "google_dataflow_job" "pubsub_to_bq" {
  name              = "pubsub-to-bigquery"
  template_gcs_path = "gs://dataflow-templates/latest/PubSub_to_BigQuery"
  temp_gcs_location = "gs://my-bucket/temp"
  ip_configuration  = "WORKER_IP_PRIVATE"
  network           = google_compute_network.data_vpc.name
  subnetwork        = google_compute_subnetwork.data_subnet.self_link
}
```

## Remediation steps
1. Set `ip_configuration = "WORKER_IP_PRIVATE"` on the `google_dataflow_job` resource.
2. Specify `network`/`subnetwork` for a VPC that has Private Google Access enabled (or a NAT gateway), so workers can still reach Dataflow's control plane and any GCP APIs they need.
3. If the pipeline reads/writes to on-prem or third-party endpoints, verify VPN/Interconnect connectivity paths exist, since the workers will no longer have a public egress IP.
4. `google_dataflow_job` resources are generally immutable to this kind of change in Terraform — expect the change to trigger job replacement (drain/relaunch) rather than an in-place update.
5. Confirm firewall rules permit the necessary internal traffic between Dataflow workers (Dataflow requires specific internal firewall rules for worker-to-worker communication).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/DataflowPrivateJob.py
- GCP docs: https://cloud.google.com/dataflow/docs/guides/routes-firewall
