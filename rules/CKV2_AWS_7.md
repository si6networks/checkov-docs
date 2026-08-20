# CKV2_AWS_7: Ensure that Amazon EMR clusters' security groups are not open to the world

## Severity
**CRITICAL** (score: 9.0/10)

An EMR cluster's security group open to 0.0.0.0/0 exposes cluster management and data-processing interfaces directly to the internet, a classic critical network-exposure misconfiguration with a well-documented history of exploited EMR/Hadoop clusters.

## Summary
This check requires that any security group attached to an `aws_emr_cluster` does not include `0.0.0.0/0` in any ingress rule's `cidr_blocks`, preventing the cluster's network interfaces from being reachable from the entire internet.

## Applicability
- **IaC framework:** Terraform
- **Resource types:** `aws_emr_cluster` (must be connected to an `aws_security_group`)

## Why it matters
EMR clusters run distributed big-data services (Hadoop, Spark, Hive, Presto/Trino, YARN ResourceManager, HDFS NameNode) that expose numerous internal management and data-plane ports (e.g., YARN UI on 8088, HDFS on 9870, Spark UI on 4040/18080, and SSH on 22 to master/core nodes). None of these services were designed to be safely exposed to the open internet — many have no authentication by default, or authentication that's trivially bypassed, and several historical EMR/Hadoop-ecosystem CVEs allow unauthenticated remote code execution or arbitrary job submission via these UIs and APIs. A security group with `0.0.0.0/0` ingress on any of these ports converts an internal analytics cluster — which typically has broad IAM permissions to read/write S3 data lakes and other data stores — into a directly internet-reachable target, one of the more common real-world routes to cryptomining compromises and data-lake breaches. Restricting ingress to known corporate CIDR ranges, VPN endpoints, or peer security groups keeps this large attack surface off the public internet.

## How Checkov evaluates this
This is a **graph-based check** (JSON policy):
1. Filters to `aws_emr_cluster` resources.
2. Requires a graph **connection** from the cluster to an `aws_security_group` (i.e., a security group referenced by the cluster's `ec2_attributes` or similar).
3. On that connected security group, requires the `ingress.*.cidr_blocks` attribute to **not contain** `"0.0.0.0/0"`.

If any ingress rule on any security group attached to the EMR cluster includes `0.0.0.0/0`, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_security_group" "emr_master" {
  name   = "emr-master-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # open to the entire internet -> FAILS
  }
}

resource "aws_emr_cluster" "analytics" {
  name          = "analytics-cluster"
  release_label = "emr-6.15.0"
  applications  = ["Spark", "Hive"]

  ec2_attributes {
    subnet_id                        = aws_subnet.private.id
    emr_managed_master_security_group = aws_security_group.emr_master.id
  }

  master_instance_group {
    instance_type = "m5.xlarge"
  }
}
```

## Remediated example
```hcl
resource "aws_security_group" "emr_master" {
  name   = "emr-master-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]   # scoped to internal VPC CIDR only
  }
}

resource "aws_emr_cluster" "analytics" {
  name          = "analytics-cluster"
  release_label = "emr-6.15.0"
  applications  = ["Spark", "Hive"]

  ec2_attributes {
    subnet_id                        = aws_subnet.private.id
    emr_managed_master_security_group = aws_security_group.emr_master.id
  }

  master_instance_group {
    instance_type = "m5.xlarge"
  }
}
```

## Remediation steps
1. Locate every security group referenced by the EMR cluster's `ec2_attributes` (master, core, and any additional security groups).
2. Replace any `cidr_blocks = ["0.0.0.0/0"]` ingress with specific, minimal CIDR ranges (corporate VPN range, bastion host IP, peer VPC CIDR) or reference other security groups via `security_groups`/`source_security_group_id` instead of open CIDRs.
3. If external access to cluster UIs is genuinely needed, front them with an authenticated reverse proxy, SSH tunnel/port-forwarding, or AWS Client VPN rather than opening the SG directly.
4. Apply the same scrutiny to any additional security groups (`additional_master_security_groups`, `additional_slave_security_groups`) since the check inspects any SG connected to the cluster.
5. Note EMR's default managed security groups are relatively permissive out of the box — always define custom, minimally-scoped security groups for production clusters rather than relying on EMR-managed defaults for internet exposure.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/AMRClustersNotOpenToInternet.json
- AWS docs: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-man-sec-groups.html
