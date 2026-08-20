# CKV_AWS_114: Ensure that EMR clusters with Kerberos have Kerberos Realm set

## Severity
**LOW** (score: 2.0/10)

An EMR cluster configured for Kerberos without a Realm set is an incomplete/misconfigured authentication setup, an availability/correctness gap rather than a direct exposure of data or credentials.

## Summary
Fails when an `aws_emr_cluster` resource defines a `kerberos_attributes` block but that block does not include a `realm` value.

## Applicability
**Checkov framework(s):** `terraform`

- **Terraform**: `aws_emr_cluster` resource.

## Why it matters
Kerberos is used with Amazon EMR to provide strong authentication for services and users within the cluster (e.g. Hadoop, Hive, HBase daemons authenticating each other, and end users authenticating to the cluster). The Kerberos "realm" is a fundamental namespace concept in Kerberos — it defines the administrative domain the KDC (Key Distribution Center) governs, and every principal (user/service) name is scoped within a realm (`user@REALM`). Configuring Kerberos without a properly set realm results in incomplete or misconfigured Kerberos setup, since the realm ties together the KDC configuration, cross-realm trust settings, and principal naming used throughout the cluster. Incomplete Kerberos configuration can lead to authentication failures being silently bypassed, cluster nodes failing to enforce mutual authentication as intended, or cluster provisioning simply failing at a later stage — undermining the security guarantee that Kerberos was added to provide in the first place.

## How Checkov evaluates this
The check inspects the `kerberos_attributes` block of the `aws_emr_cluster` resource:
- **UNKNOWN** if the resource has no `kerberos_attributes` block at all (Kerberos isn't being used, so the check doesn't apply).
- **PASS** if `kerberos_attributes` is present and contains a `realm` key.
- **FAIL** if `kerberos_attributes` is present but `realm` is missing.

## Non-compliant example
```hcl
resource "aws_emr_security_configuration" "kerberos" {
  name = "emrKerberos"
  configuration = jsonencode({
    AuthenticationConfiguration = {
      KerberosConfiguration = {
        Provider = "ClusterDedicatedKdc"
        ClusterDedicatedKdcConfiguration = {
          TicketLifetimeInHours = 24
        }
      }
    }
  })
}

resource "aws_emr_cluster" "bad" {
  name          = "emr-kerberos-cluster"
  release_label = "emr-6.10.0"
  applications  = ["Hadoop", "Hive"]

  security_configuration = aws_emr_security_configuration.kerberos.name

  kerberos_attributes {
    kdc_admin_password = var.kdc_admin_password
    # realm is missing
  }

  # ... other required attributes omitted for brevity
}
```

## Remediated example
```hcl
resource "aws_emr_cluster" "good" {
  name          = "emr-kerberos-cluster"
  release_label = "emr-6.10.0"
  applications  = ["Hadoop", "Hive"]

  security_configuration = aws_emr_security_configuration.kerberos.name

  kerberos_attributes {
    kdc_admin_password = var.kdc_admin_password
    realm               = "EC2.INTERNAL"
  }

  # ... other required attributes omitted for brevity
}
```

## Remediation steps
1. Add a `realm` attribute to the `kerberos_attributes` block, e.g. `"EC2.INTERNAL"` for a cluster-dedicated KDC, or your organization's registered Kerberos realm name if federating with an external KDC.
2. If cross-realm trust is required (external Active Directory KDC), also set `ad_domain_join_password`/`ad_domain_join_user` and `cross_realm_trust_principal_password` as appropriate — the realm must be consistent with the security configuration's `KerberosConfiguration`.
3. This attribute is set at cluster creation time and generally requires cluster replacement if changed after the fact, so validate the realm value before initial `apply`.
4. Confirm the value matches whatever is referenced in the associated `aws_emr_security_configuration`'s Kerberos block for consistency.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/EMRClusterKerberosAttributes.py
- AWS documentation: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-kerberos.html
