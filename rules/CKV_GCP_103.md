# CKV_GCP_103: Ensure Dataproc Clusters do not have public IPs

## Severity
**HIGH** (score: 7.5/10)

Assigning public IP addresses to Dataproc cluster nodes exposes cluster management and data-processing interfaces directly to the internet instead of keeping them on a private network.

## Summary
This check ensures that a `google_dataproc_cluster` resource is configured with `internal_ip_only = true` in its `gce_cluster_config`, so cluster nodes are not assigned public/external IP addresses.

## Applicability
- **IaC framework**: Terraform
- **Resource type**: `google_dataproc_cluster`
- **Attribute inspected**: `cluster_config.gce_cluster_config.internal_ip_only`

## Why it matters
Dataproc clusters run Hadoop/Spark workloads that often process large volumes of potentially sensitive data and expose several service ports (YARN, HDFS NameNode UI, Spark History Server, Jupyter/Zeppelin if enabled) on their nodes. If `internal_ip_only` is not enabled, each cluster VM receives an external IP address, meaning:

- **Directly internet-reachable compute nodes**: Absent tightly-scoped firewall rules, cluster nodes with public IPs are reachable from the internet, exposing big-data management UIs and APIs that are typically unauthenticated or weakly authenticated by default, a common source of publicly-indexed exposed Hadoop clusters used for cryptomining or data theft.
- **Larger attack surface for lateral movement**: A compromised node with a public IP can be used more easily as an internet-facing pivot point, and is more discoverable by internet-wide scanners (Shodan, masscan) than an internal-only node.
- **Egress data exfiltration risk**: Nodes with direct public IPs can communicate directly outbound to the internet without necessarily transiting a controlled NAT gateway or Cloud NAT logging point, making data exfiltration harder to detect and control.
- **Violates cloud network segmentation best practice**: Compute meant to process internal data pipelines should generally have no more network exposure than required; internal-only clusters that egress via Cloud NAT (with logging) preserve visibility and control.

## How Checkov evaluates this
The check (`DataprocPublicIpCluster`) is a positive-value check that looks at the attribute path `cluster_config/[0]/gce_cluster_config/[0]/internal_ip_only`:
- **PASSES** if `internal_ip_only = true` is set within `gce_cluster_config`.
- **FAILS** if the attribute is absent or set to `false`.

## Non-compliant example
```hcl
resource "google_dataproc_cluster" "analytics" {
  name   = "analytics-cluster"
  region = "us-central1"

  cluster_config {
    gce_cluster_config {
      zone                   = "us-central1-a"
      internal_ip_only       = false
      subnetwork             = google_compute_subnetwork.dataproc.self_link
    }
  }
}
```

## Remediated example
```hcl
resource "google_dataproc_cluster" "analytics" {
  name   = "analytics-cluster"
  region = "us-central1"

  cluster_config {
    gce_cluster_config {
      zone              = "us-central1-a"
      internal_ip_only  = true
      subnetwork        = google_compute_subnetwork.dataproc.self_link
    }
  }
}
```

## Remediation steps
1. Set `internal_ip_only = true` within the `gce_cluster_config` block of the `google_dataproc_cluster` resource.
2. Ensure Private Google Access is enabled on the cluster's subnetwork (`private_ip_google_access = true` on the `google_compute_subnetwork`) so nodes can still reach Google APIs (GCS, BigQuery, etc.) without a public IP.
3. Provision a Cloud NAT gateway on the cluster's VPC/region if the cluster nodes need outbound internet access (e.g., to pull external packages), so egress is still possible but centrally logged and controlled.
4. This setting typically requires cluster recreation if changed on an existing cluster (Dataproc cluster network configuration is generally immutable post-creation) — plan for a maintenance window and data/job migration rather than an in-place update.
5. Re-scan with Checkov and confirm connectivity from internal-only nodes to any downstream GCP services or on-prem systems used by your data pipelines.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/gcp/DataprocPublicIpCluster.py
- GCP Dataproc internal IP only documentation: https://cloud.google.com/dataproc/docs/concepts/configuring-clusters/network
