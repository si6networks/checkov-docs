# CKV_AWS_164: Ensure Transfer Server is not exposed publicly

## Severity
**HIGH** (score: 7.5/10)

A Transfer Server configured with a PUBLIC endpoint type exposes an SFTP/FTPS file-transfer service directly to the internet, giving any external party network reachability to a service that handles file uploads/downloads of potentially sensitive data.

## Summary
This check requires that an AWS Transfer Family (SFTP/FTPS/FTP) server's endpoint type be `VPC` or `VPC_ENDPOINT` rather than the internet-facing `PUBLIC` endpoint type.

## Applicability
- **Terraform**: `aws_transfer_server`
- **CloudFormation**: `AWS::Transfer::Server`

## Why it matters
AWS Transfer Family servers provide managed SFTP/FTPS/FTP endpoints for file transfer, frequently used to exchange sensitive data (financial files, PII, EDI documents) with external partners. When the endpoint type is `PUBLIC`, the server is reachable directly from the internet on a shared AWS-owned IP range, with access control resting entirely on the transfer server's own authentication (SSH keys, passwords, or custom identity provider) and any host-key/IP restrictions layered on top.

Placing the server inside a VPC (`VPC` or `VPC_ENDPOINT` endpoint type) allows the file-transfer endpoint to sit behind security groups, NACLs, and (for `VPC_ENDPOINT`) a private VPC endpoint with resource-based endpoint policies — enabling defense-in-depth network controls (allow-listing specific partner IPs, keeping the endpoint entirely private, routing through existing network monitoring/inspection) that are not possible with the shared public endpoint. A public, internet-reachable file transfer endpoint is a common reconnaissance and brute-force target, and removing network-layer controls means every authentication weakness (weak keys, credential stuffing) becomes directly internet-exploitable.

## How Checkov evaluates this
The check inspects the `endpoint_type` attribute (Terraform) / `Properties.EndpointType` (CloudFormation) on the Transfer Server resource. It **PASSES** only if the value is exactly `"VPC"` or `"VPC_ENDPOINT"`; any other value (notably `"PUBLIC"`, or omitting the attribute since `PUBLIC` is the AWS default) causes the check to **FAIL**.

## Non-compliant example
```hcl
resource "aws_transfer_server" "sftp" {
  identity_provider_type = "SERVICE_MANAGED"
  protocols               = ["SFTP"]
  # endpoint_type not set -> defaults to PUBLIC
}
```

## Remediated example
```hcl
resource "aws_transfer_server" "sftp" {
  identity_provider_type = "SERVICE_MANAGED"
  protocols               = ["SFTP"]
  endpoint_type           = "VPC"  # added: place server inside a VPC

  endpoint_details {
    vpc_id     = aws_vpc.main.id
    subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  }
}
```

## Remediation steps
1. Set `endpoint_type = "VPC"` (or `"VPC_ENDPOINT"` for a fully private, endpoint-policy-controlled option) instead of leaving it unset or `"PUBLIC"`.
2. Add an `endpoint_details` block specifying `vpc_id` and one or more `subnet_ids` for the elastic network interfaces the server will use.
3. Attach a security group to the endpoint restricting inbound access (e.g. SFTP/22) to only the partner IP ranges or internal networks that need access.
4. If external partners need access without a VPN/Direct Connect, consider attaching an Elastic IP to the VPC endpoint or fronting with a NAT/security-group-controlled path — `VPC` endpoint type still supports internet-reachable EIPs but under your own security group control, unlike the shared `PUBLIC` type.
5. Note: changing `endpoint_type` on an existing server is disruptive — it changes the server's endpoint/IP addresses, so DNS records and partner firewall allow-lists pointing at the old public endpoint will need to be updated, and there will be a cutover window.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/TransferServerIsPublic.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/TransferServerIsPublic.py
- AWS docs: https://docs.aws.amazon.com/transfer/latest/userguide/create-server-vpc-endpoint.html
