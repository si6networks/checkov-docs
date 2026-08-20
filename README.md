# Checkov Rule Reference

A local reference library for Checkov (bridgecrewio/checkov) static-analysis rule IDs, generated because the vendor's public rule documentation site went offline. Covers **1359 rules** across **32 categories**, each with a severity rating (sourced from vendor security-rule metadata where available, otherwise assessed using established security-severity judgment) and a detailed remediation guide.

## Table of Contents

- [ADO](#ado)
- [ALI](#ali)
- [ANSIBLE](#ansible)
- [ARGO](#argo)
- [AWS](#aws)
- [AZURE](#azure)
- [AZUREPIPELINES](#azurepipelines)
- [BCW](#bcw)
- [BITBUCKET](#bitbucket)
- [BITBUCKETPIPELINES](#bitbucketpipelines)
- [CIRCLECIPIPELINES](#circlecipipelines)
- [DIO](#dio)
- [DOCKER](#docker)
- [GCP](#gcp)
- [GHA](#gha)
- [GIT](#git)
- [GITHUB](#github)
- [GITLAB](#gitlab)
- [GITLABCI](#gitlabci)
- [GLB](#glb)
- [IBM](#ibm)
- [K8S](#k8s)
- [LIN](#lin)
- [NCP](#ncp)
- [OCI](#oci)
- [OPENAPI](#openapi)
- [OPENSTACK](#openstack)
- [PAN](#pan)
- [SECRET](#secret)
- [TC](#tc)
- [TF](#tf)
- [YC](#yc)

## ADO

| Rule ID | Severity | Description |
|---|---|---|
| [CKV2_ADO_1](./rules/CKV2_ADO_1.md) | MEDIUM (4.5/10) | Ensure at least two approving reviews for PRs |

## ALI

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_ALI_1](./rules/CKV_ALI_1.md) | CRITICAL (9/10) | Alibaba Cloud OSS bucket accessible to public |
| [CKV_ALI_2](./rules/CKV_ALI_2.md) | CRITICAL (9/10) | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 |
| [CKV_ALI_3](./rules/CKV_ALI_3.md) | CRITICAL (9/10) | Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 |
| [CKV_ALI_4](./rules/CKV_ALI_4.md) | MEDIUM (5.0/10) | Ensure Action Trail Logging for all regions |
| [CKV_ALI_5](./rules/CKV_ALI_5.md) | MEDIUM (5.0/10) | Ensure Action Trail Logging for all events |
| [CKV_ALI_6](./rules/CKV_ALI_6.md) | MEDIUM (5.0/10) | Ensure OSS bucket is encrypted with Customer Master Key |
| [CKV_ALI_7](./rules/CKV_ALI_7.md) | LOW (2.0/10) | Ensure disk is encrypted |
| [CKV_ALI_8](./rules/CKV_ALI_8.md) | LOW (2.0/10) | Ensure Disk is encrypted with Customer Master Key |
| [CKV_ALI_9](./rules/CKV_ALI_9.md) | CRITICAL (9.1/10) | Ensure database instance is not public |
| [CKV_ALI_10](./rules/CKV_ALI_10.md) | LOW (2.0/10) | Ensure OSS bucket has versioning enabled |
| [CKV_ALI_11](./rules/CKV_ALI_11.md) | LOW (2.0/10) | Ensure OSS bucket has transfer Acceleration enabled |
| [CKV_ALI_12](./rules/CKV_ALI_12.md) | LOW (2.0/10) | Ensure the OSS bucket has access logging enabled |
| [CKV_ALI_13](./rules/CKV_ALI_13.md) | LOW (2.0/10) | Ensure RAM password policy requires minimum length of 14 or greater |
| [CKV_ALI_14](./rules/CKV_ALI_14.md) | MEDIUM (5.0/10) | Ensure RAM password policy requires at least one number |
| [CKV_ALI_15](./rules/CKV_ALI_15.md) | LOW (2.0/10) | Ensure RAM password policy requires at least one symbol |
| [CKV_ALI_16](./rules/CKV_ALI_16.md) | LOW (2.0/10) | Ensure RAM password policy expires passwords within 90 days or less |
| [CKV_ALI_17](./rules/CKV_ALI_17.md) | LOW (2.0/10) | Ensure RAM password policy requires at least one lowercase letter |
| [CKV_ALI_18](./rules/CKV_ALI_18.md) | MEDIUM (5.0/10) | Ensure RAM password policy prevents password reuse |
| [CKV_ALI_19](./rules/CKV_ALI_19.md) | MEDIUM (5.0/10) | Ensure RAM password policy requires at least one uppercase letter |
| [CKV_ALI_20](./rules/CKV_ALI_20.md) | HIGH (7.5/10) | Ensure RDS instance uses SSL |
| [CKV_ALI_21](./rules/CKV_ALI_21.md) | HIGH (7.5/10) | Ensure API Gateway API Protocol HTTPS |
| [CKV_ALI_22](./rules/CKV_ALI_22.md) | LOW (2.0/10) | Ensure Transparent Data Encryption is Enabled on instance |
| [CKV_ALI_23](./rules/CKV_ALI_23.md) | MEDIUM (5.0/10) | Ensure Ram Account Password Policy Max Login Attempts not > 5 |
| [CKV_ALI_24](./rules/CKV_ALI_24.md) | LOW (2.0/10) | Ensure RAM enforces MFA |
| [CKV_ALI_25](./rules/CKV_ALI_25.md) | LOW (2.0/10) | Ensure RDS Instance SQL Collector Retention Period should be greater than 180 |
| [CKV_ALI_26](./rules/CKV_ALI_26.md) | LOW (2.0/10) | Ensure Kubernetes installs plugin Terway or Flannel to support standard policies |
| [CKV_ALI_27](./rules/CKV_ALI_27.md) | LOW (2.0/10) | Ensure KMS Key Rotation is enabled |
| [CKV_ALI_28](./rules/CKV_ALI_28.md) | LOW (2.0/10) | Ensure KMS Keys are enabled |
| [CKV_ALI_29](./rules/CKV_ALI_29.md) | HIGH (7/10) | Alibaba ALB ACL does not restrict Access |
| [CKV_ALI_30](./rules/CKV_ALI_30.md) | LOW (2.0/10) | Ensure RDS instance auto upgrades for minor versions |
| [CKV_ALI_31](./rules/CKV_ALI_31.md) | LOW (2.0/10) | Ensure K8s nodepools are set to auto repair |
| [CKV_ALI_32](./rules/CKV_ALI_32.md) | LOW (2.0/10) | Ensure launch template data disks are encrypted |
| [CKV_ALI_33](./rules/CKV_ALI_33.md) | LOW (2.0/10) | Alibaba Cloud Cypher Policy are secure |
| [CKV_ALI_35](./rules/CKV_ALI_35.md) | LOW (2.0/10) | Ensure RDS instance has log_duration enabled |
| [CKV_ALI_36](./rules/CKV_ALI_36.md) | LOW (2.0/10) | Ensure RDS instance has log_disconnections enabled |
| [CKV_ALI_37](./rules/CKV_ALI_37.md) | LOW (2.0/10) | Ensure RDS instance has log_connections enabled |
| [CKV_ALI_38](./rules/CKV_ALI_38.md) | LOW (2.0/10) | Ensure log audit is enabled for RDS |
| [CKV_ALI_41](./rules/CKV_ALI_41.md) | LOW (2.0/10) | Ensure MongoDB is deployed inside a VPC |
| [CKV_ALI_42](./rules/CKV_ALI_42.md) | HIGH (7.5/10) | Ensure Mongodb instance uses SSL |
| [CKV_ALI_43](./rules/CKV_ALI_43.md) | CRITICAL (9.1/10) | Ensure MongoDB instance is not public |
| [CKV_ALI_44](./rules/CKV_ALI_44.md) | LOW (2.0/10) | Ensure MongoDB has Transparent Data Encryption Enabled |

## ANSIBLE

| Rule ID | Severity | Description |
|---|---|---|
| [CKV2_ANSIBLE_1](./rules/CKV2_ANSIBLE_1.md) | MEDIUM (5.5/10) | Ensure that HTTPS url is used with uri |
| [CKV_ANSIBLE_1](./rules/CKV_ANSIBLE_1.md) | MEDIUM (5.0/10) | Ensure that certificate validation isn't disabled with uri |
| [CKV2_ANSIBLE_2](./rules/CKV2_ANSIBLE_2.md) | MEDIUM (5.5/10) | Ensure that HTTPS url is used with get_url |
| [CKV_ANSIBLE_2](./rules/CKV_ANSIBLE_2.md) | MEDIUM (5.0/10) | Ensure that certificate validation isn't disabled with get_url |
| [CKV2_ANSIBLE_3](./rules/CKV2_ANSIBLE_3.md) | LOW (2.5/10) | Ensure block is handling task errors properly |
| [CKV_ANSIBLE_3](./rules/CKV_ANSIBLE_3.md) | MEDIUM (5.0/10) | Ensure that certificate validation isn't disabled with yum |
| [CKV2_ANSIBLE_4](./rules/CKV2_ANSIBLE_4.md) | MEDIUM (5.0/10) | Ensure that packages with untrusted or missing GPG signatures are not used by dnf |
| [CKV_ANSIBLE_4](./rules/CKV_ANSIBLE_4.md) | MEDIUM (5.0/10) | Ensure that SSL validation isn't disabled with yum |
| [CKV2_ANSIBLE_5](./rules/CKV2_ANSIBLE_5.md) | MEDIUM (5.0/10) | Ensure that SSL validation isn't disabled with dnf |
| [CKV_ANSIBLE_5](./rules/CKV_ANSIBLE_5.md) | LOW (2.0/10) | Ensure that packages with untrusted or missing signatures are not used |
| [CKV2_ANSIBLE_6](./rules/CKV2_ANSIBLE_6.md) | MEDIUM (5.0/10) | Ensure that certificate validation isn't disabled with dnf |
| [CKV_ANSIBLE_6](./rules/CKV_ANSIBLE_6.md) | LOW (2.0/10) | Ensure that the force parameter is not used, as it disables signature validation and allows packages to be downgraded |

## ARGO

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_ARGO_1](./rules/CKV_ARGO_1.md) | MEDIUM (5.5/10) | Ensure Workflow pods are not using the default ServiceAccount |
| [CKV_ARGO_2](./rules/CKV_ARGO_2.md) | HIGH (7.5/10) | Ensure Workflow pods are running as non-root user |

## AWS

| Rule ID | Severity | Description |
|---|---|---|
| [CKV2_AWS_1](./rules/CKV2_AWS_1.md) | MEDIUM (4.5/10) | Ensure that all NACL are attached to subnets |
| [CKV_AWS_1](./rules/CKV_AWS_1.md) | LOW (2.0/10) | Ensure IAM policies that allow full "*-*" administrative privileges are not created |
| [CKV2_AWS_2](./rules/CKV2_AWS_2.md) | LOW (2.0/10) | Ensure that only encrypted EBS volumes are attached to EC2 instances |
| [CKV_AWS_2](./rules/CKV_AWS_2.md) | HIGH (7.5/10) | Ensure ALB protocol is HTTPS |
| [CKV2_AWS_3](./rules/CKV2_AWS_3.md) | LOW (2.0/10) | Ensure GuardDuty is enabled to specific org/region |
| [CKV_AWS_3](./rules/CKV_AWS_3.md) | HIGH (7.5/10) | Ensure all data stored in the EBS is securely encrypted |
| [CKV2_AWS_4](./rules/CKV2_AWS_4.md) | LOW (2.0/10) | Ensure API Gateway stage have logging level defined as appropriate |
| [CKV2_AWS_5](./rules/CKV2_AWS_5.md) | LOW (2/10) | Ensure that Security Groups are attached to another resource |
| [CKV_AWS_5](./rules/CKV_AWS_5.md) | LOW (2.0/10) | Ensure all data stored in the Elasticsearch is securely encrypted at rest |
| [CKV2_AWS_6](./rules/CKV2_AWS_6.md) | CRITICAL (9.1/10) | Ensure that S3 bucket has a Public Access block |
| [CKV_AWS_6](./rules/CKV_AWS_6.md) | HIGH (7.5/10) | Ensure all Elasticsearch has node-to-node encryption enabled |
| [CKV2_AWS_7](./rules/CKV2_AWS_7.md) | CRITICAL (9/10) | Ensure that Amazon EMR clusters' security groups are not open to the world |
| [CKV_AWS_7](./rules/CKV_AWS_7.md) | LOW (2.0/10) | Ensure rotation for customer created CMKs is enabled |
| [CKV2_AWS_8](./rules/CKV2_AWS_8.md) | LOW (2.0/10) | Ensure that RDS clusters has backup plan of AWS Backup |
| [CKV_AWS_8](./rules/CKV_AWS_8.md) | LOW (2.0/10) | Ensure all data stored in the Launch configuration or instance Elastic Blocks Store is securely encrypted |
| [CKV2_AWS_9](./rules/CKV2_AWS_9.md) | LOW (2.0/10) | Ensure that EBS are added in the backup plans of AWS Backup |
| [CKV_AWS_9](./rules/CKV_AWS_9.md) | LOW (2.0/10) | Ensure IAM password policy expires passwords within 90 days or less |
| [CKV2_AWS_10](./rules/CKV2_AWS_10.md) | LOW (2.0/10) | Ensure CloudTrail trails are integrated with CloudWatch Logs |
| [CKV_AWS_10](./rules/CKV_AWS_10.md) | LOW (2.0/10) | Ensure IAM password policy requires minimum length of 14 or greater |
| [CKV2_AWS_11](./rules/CKV2_AWS_11.md) | LOW (2.0/10) | Ensure VPC flow logging is enabled in all VPCs |
| [CKV_AWS_11](./rules/CKV_AWS_11.md) | LOW (2.0/10) | Ensure IAM password policy requires at least one lowercase letter |
| [CKV2_AWS_12](./rules/CKV2_AWS_12.md) | HIGH (7.5/10) | Ensure the default security group of every VPC restricts all traffic |
| [CKV_AWS_12](./rules/CKV_AWS_12.md) | LOW (2.0/10) | Ensure IAM password policy requires at least one number |
| [CKV_AWS_13](./rules/CKV_AWS_13.md) | HIGH (7.5/10) | Ensure IAM password policy prevents password reuse |
| [CKV2_AWS_14](./rules/CKV2_AWS_14.md) | LOW (2.0/10) | Ensure that IAM groups includes at least one IAM user |
| [CKV_AWS_14](./rules/CKV_AWS_14.md) | LOW (2.0/10) | Ensure IAM password policy requires at least one symbol |
| [CKV2_AWS_15](./rules/CKV2_AWS_15.md) | MEDIUM (3.5/10) | Ensure that auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing health checks. |
| [CKV_AWS_15](./rules/CKV_AWS_15.md) | LOW (2.0/10) | Ensure IAM password policy requires at least one uppercase letter |
| [CKV2_AWS_16](./rules/CKV2_AWS_16.md) | LOW (2.0/10) | Ensure that Auto Scaling is enabled on your DynamoDB tables |
| [CKV_AWS_16](./rules/CKV_AWS_16.md) | LOW (2.0/10) | Ensure all data stored in the RDS is securely encrypted at rest |
| [CKV_AWS_17](./rules/CKV_AWS_17.md) | CRITICAL (9/10) | Ensure all data stored in RDS is not publicly accessible |
| [CKV2_AWS_18](./rules/CKV2_AWS_18.md) | LOW (2.0/10) | Ensure that Elastic File System (Amazon EFS) file systems are added in the backup plans of AWS Backup |
| [CKV_AWS_18](./rules/CKV_AWS_18.md) | LOW (2.0/10) | Ensure the S3 bucket has access logging enabled |
| [CKV2_AWS_19](./rules/CKV2_AWS_19.md) | LOW (2/10) | Ensure that all EIP addresses allocated to a VPC are attached to EC2 instances |
| [CKV_AWS_19](./rules/CKV_AWS_19.md) | LOW (2.0/10) | Ensure all data stored in the S3 bucket is securely encrypted at rest |
| [CKV2_AWS_20](./rules/CKV2_AWS_20.md) | MEDIUM (5/10) | Ensure that ALB redirects HTTP requests into HTTPS ones |
| [CKV_AWS_20](./rules/CKV_AWS_20.md) | HIGH (7.5/10) | Ensure the S3 bucket does not allow READ permissions to everyone |
| [CKV2_AWS_21](./rules/CKV2_AWS_21.md) | LOW (2.0/10) | Ensure that all IAM users are members of at least one IAM group |
| [CKV_AWS_21](./rules/CKV_AWS_21.md) | LOW (2.0/10) | Ensure all data stored in the S3 bucket have versioning enabled |
| [CKV2_AWS_22](./rules/CKV2_AWS_22.md) | MEDIUM (5.0/10) | Ensure an IAM User does not have access to the console |
| [CKV_AWS_22](./rules/CKV_AWS_22.md) | LOW (2.0/10) | Ensure SageMaker Notebook is encrypted at rest using KMS CMK |
| [CKV2_AWS_23](./rules/CKV2_AWS_23.md) | HIGH (7.5/10) | Route53 A Record has Attached Resource |
| [CKV_AWS_23](./rules/CKV_AWS_23.md) | LOW (2/10) | Ensure every security group and rule has a description |
| [CKV_AWS_24](./rules/CKV_AWS_24.md) | CRITICAL (9.2/10) | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 |
| [CKV_AWS_25](./rules/CKV_AWS_25.md) | CRITICAL (9.5/10) | Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 |
| [CKV_AWS_26](./rules/CKV_AWS_26.md) | MEDIUM (5.0/10) | Ensure all data stored in the SNS topic is encrypted |
| [CKV2_AWS_27](./rules/CKV2_AWS_27.md) | LOW (2.0/10) | Ensure Postgres RDS as aws_rds_cluster has Query Logging enabled |
| [CKV_AWS_27](./rules/CKV_AWS_27.md) | LOW (2.0/10) | Ensure all data stored in the SQS queue is encrypted |
| [CKV2_AWS_28](./rules/CKV2_AWS_28.md) | HIGH (7.5/10) | Ensure public facing ALB are protected by WAF |
| [CKV_AWS_28](./rules/CKV_AWS_28.md) | HIGH (7.5/10) | Ensure DynamoDB point in time recovery (backup) is enabled |
| [CKV2_AWS_29](./rules/CKV2_AWS_29.md) | HIGH (7.5/10) | Ensure public API gateway are protected by WAF |
| [CKV_AWS_29](./rules/CKV_AWS_29.md) | LOW (2.0/10) | Ensure all data stored in the ElastiCache Replication Group is securely encrypted at rest |
| [CKV2_AWS_30](./rules/CKV2_AWS_30.md) | LOW (2.0/10) | Ensure Postgres RDS as aws_db_instance has Query Logging enabled |
| [CKV_AWS_30](./rules/CKV_AWS_30.md) | HIGH (7.5/10) | Ensure all data stored in the ElastiCache Replication Group is securely encrypted at transit |
| [CKV2_AWS_31](./rules/CKV2_AWS_31.md) | LOW (2.0/10) | Ensure WAF2 has a Logging Configuration |
| [CKV_AWS_31](./rules/CKV_AWS_31.md) | HIGH (7.8/10) | Ensure all data stored in the ElastiCache Replication Group is securely encrypted at transit and has auth token |
| [CKV2_AWS_32](./rules/CKV2_AWS_32.md) | MEDIUM (5/10) | Ensure CloudFront distribution has a response headers policy attached |
| [CKV_AWS_32](./rules/CKV_AWS_32.md) | MEDIUM (5.0/10) | Ensure ECR policy is not set to public |
| [CKV2_AWS_33](./rules/CKV2_AWS_33.md) | LOW (2.0/10) | Ensure AppSync is protected by WAF |
| [CKV_AWS_33](./rules/CKV_AWS_33.md) | MEDIUM (5.0/10) | Ensure KMS key policy does not contain wildcard (*) principal |
| [CKV2_AWS_34](./rules/CKV2_AWS_34.md) | LOW (2.0/10) | AWS SSM Parameter should be Encrypted |
| [CKV_AWS_34](./rules/CKV_AWS_34.md) | HIGH (7/10) | Ensure CloudFront Distribution ViewerProtocolPolicy is set to HTTPS |
| [CKV2_AWS_35](./rules/CKV2_AWS_35.md) | LOW (2.0/10) | AWS NAT Gateways should be utilized for the default route |
| [CKV_AWS_35](./rules/CKV_AWS_35.md) | LOW (2.0/10) | Ensure CloudTrail logs are encrypted at rest using KMS CMKs |
| [CKV2_AWS_36](./rules/CKV2_AWS_36.md) | CRITICAL (9/10) | Ensure terraform is not sending SSM secrets to untrusted domains over HTTP |
| [CKV_AWS_36](./rules/CKV_AWS_36.md) | LOW (2.0/10) | Ensure CloudTrail log file validation is enabled |
| [CKV2_AWS_37](./rules/CKV2_AWS_37.md) | LOW (2.0/10) | Ensure CodeCommit associates an approval rule |
| [CKV_AWS_37](./rules/CKV_AWS_37.md) | LOW (2.0/10) | Ensure Amazon EKS control plane logging is enabled for all log types |
| [CKV2_AWS_38](./rules/CKV2_AWS_38.md) | MEDIUM (6/10) | Ensure Domain Name System Security Extensions (DNSSEC) signing is enabled for Amazon Route 53 public hosted zones |
| [CKV_AWS_38](./rules/CKV_AWS_38.md) | LOW (2.0/10) | Ensure Amazon EKS public endpoint not accessible to 0.0.0.0/0 |
| [CKV2_AWS_39](./rules/CKV2_AWS_39.md) | LOW (2.0/10) | Ensure Domain Name System (DNS) query logging is enabled for Amazon Route 53 hosted zones |
| [CKV_AWS_39](./rules/CKV_AWS_39.md) | HIGH (7.5/10) | Ensure Amazon EKS public endpoint disabled |
| [CKV2_AWS_40](./rules/CKV2_AWS_40.md) | MEDIUM (5.0/10) | Ensure AWS IAM policy does not allow full IAM privileges |
| [CKV_AWS_40](./rules/CKV_AWS_40.md) | LOW (2.0/10) | Ensure IAM policies are attached only to groups or roles |
| [CKV2_AWS_41](./rules/CKV2_AWS_41.md) | LOW (2.0/10) | Ensure an IAM role is attached to EC2 instance |
| [CKV_AWS_41](./rules/CKV_AWS_41.md) | CRITICAL (9.5/10) | Ensure no hard coded AWS access key and secret key exists in provider |
| [CKV2_AWS_42](./rules/CKV2_AWS_42.md) | MEDIUM (4.5/10) | Ensure AWS CloudFront distribution uses custom SSL certificate |
| [CKV_AWS_42](./rules/CKV_AWS_42.md) | LOW (2.0/10) | Ensure EFS is securely encrypted |
| [CKV2_AWS_43](./rules/CKV2_AWS_43.md) | MEDIUM (5.0/10) | Ensure S3 Bucket does not allow access to all Authenticated users |
| [CKV_AWS_43](./rules/CKV_AWS_43.md) | LOW (2.0/10) | Ensure Kinesis Stream is securely encrypted |
| [CKV2_AWS_44](./rules/CKV2_AWS_44.md) | HIGH (7.2/10) | Ensure AWS route table with VPC peering does not contain routes overly permissive to all traffic |
| [CKV_AWS_44](./rules/CKV_AWS_44.md) | MEDIUM (5.0/10) | Ensure Neptune storage is securely encrypted |
| [CKV2_AWS_45](./rules/CKV2_AWS_45.md) | LOW (2.0/10) | Ensure AWS Config recorder is enabled to record all supported resources |
| [CKV_AWS_45](./rules/CKV_AWS_45.md) | CRITICAL (9.3/10) | Ensure no hard-coded secrets exist in Lambda environment |
| [CKV2_AWS_46](./rules/CKV2_AWS_46.md) | LOW (2.0/10) | Ensure AWS CloudFront Distribution with S3 have Origin Access set to enabled |
| [CKV_AWS_46](./rules/CKV_AWS_46.md) | CRITICAL (9/10) | Ensure no hard-coded secrets exist in EC2 user data |
| [CKV2_AWS_47](./rules/CKV2_AWS_47.md) | MEDIUM (5.0/10) | Ensure AWS CloudFront attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability |
| [CKV_AWS_47](./rules/CKV_AWS_47.md) | LOW (2.0/10) | Ensure DAX is encrypted at rest (default is unencrypted) |
| [CKV2_AWS_48](./rules/CKV2_AWS_48.md) | LOW (2.0/10) | Ensure AWS Config must record all possible resources |
| [CKV_AWS_48](./rules/CKV_AWS_48.md) | MEDIUM (5.0/10) | Ensure MQ Broker logging is enabled |
| [CKV2_AWS_49](./rules/CKV2_AWS_49.md) | HIGH (7/10) | Ensure AWS Database Migration Service endpoints have SSL configured |
| [CKV_AWS_49](./rules/CKV_AWS_49.md) | HIGH (7.5/10) | Ensure no IAM policies documents allow "*" as a statement's actions |
| [CKV2_AWS_50](./rules/CKV2_AWS_50.md) | LOW (2.0/10) | Ensure AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to enabled |
| [CKV_AWS_50](./rules/CKV_AWS_50.md) | LOW (2.0/10) | X-Ray tracing is enabled for Lambda |
| [CKV2_AWS_51](./rules/CKV2_AWS_51.md) | MEDIUM (5/10) | Ensure AWS API Gateway endpoints uses client certificate authentication |
| [CKV_AWS_51](./rules/CKV_AWS_51.md) | LOW (2.0/10) | Ensure ECR Image Tags are immutable |
| [CKV2_AWS_52](./rules/CKV2_AWS_52.md) | LOW (2.0/10) | Ensure AWS ElasticSearch/OpenSearch Fine-grained access control is enabled |
| [CKV2_AWS_53](./rules/CKV2_AWS_53.md) | MEDIUM (5/10) | Ensure AWS API gateway request is validated |
| [CKV_AWS_53](./rules/CKV_AWS_53.md) | MEDIUM (5.0/10) | Ensure S3 bucket has block public ACLs enabled |
| [CKV2_AWS_54](./rules/CKV2_AWS_54.md) | HIGH (7.4/10) | Ensure AWS CloudFront distribution is using secure SSL protocols for HTTPS communication |
| [CKV_AWS_54](./rules/CKV_AWS_54.md) | MEDIUM (5.0/10) | Ensure S3 bucket has block public policy enabled |
| [CKV2_AWS_55](./rules/CKV2_AWS_55.md) | LOW (2.0/10) | Ensure AWS EMR cluster is configured with security configuration |
| [CKV_AWS_55](./rules/CKV_AWS_55.md) | MEDIUM (5.0/10) | Ensure S3 bucket has ignore public ACLs enabled |
| [CKV2_AWS_56](./rules/CKV2_AWS_56.md) | HIGH (7.5/10) | Ensure AWS Managed IAMFullAccess IAM policy is not used. |
| [CKV_AWS_56](./rules/CKV_AWS_56.md) | MEDIUM (5.0/10) | Ensure S3 bucket has 'restrict_public_buckets' enabled |
| [CKV2_AWS_57](./rules/CKV2_AWS_57.md) | LOW (2.0/10) | Ensure Secrets Manager secrets should have automatic rotation enabled |
| [CKV_AWS_57](./rules/CKV_AWS_57.md) | HIGH (7.5/10) | Ensure the S3 bucket does not allow WRITE permissions to everyone |
| [CKV2_AWS_58](./rules/CKV2_AWS_58.md) | LOW (2.0/10) | Ensure AWS Neptune cluster deletion protection is enabled |
| [CKV_AWS_58](./rules/CKV_AWS_58.md) | MEDIUM (5.0/10) | Ensure EKS Cluster has Secrets Encryption Enabled |
| [CKV2_AWS_59](./rules/CKV2_AWS_59.md) | LOW (2.0/10) | Ensure ElasticSearch/OpenSearch has dedicated master node enabled |
| [CKV_AWS_59](./rules/CKV_AWS_59.md) | CRITICAL (9.5/10) | Ensure there is no open access to back-end resources through API |
| [CKV2_AWS_60](./rules/CKV2_AWS_60.md) | LOW (2.0/10) | Ensure RDS instance with copy tags to snapshots is enabled |
| [CKV_AWS_60](./rules/CKV_AWS_60.md) | HIGH (7.5/10) | Ensure IAM role allows only specific services or principals to assume it |
| [CKV2_AWS_61](./rules/CKV2_AWS_61.md) | MEDIUM (5.0/10) | Ensure that an S3 bucket has a lifecycle configuration |
| [CKV_AWS_61](./rules/CKV_AWS_61.md) | HIGH (7.5/10) | Ensure AWS IAM policy does not allow assume role permission across all services |
| [CKV2_AWS_62](./rules/CKV2_AWS_62.md) | LOW (2.0/10) | Ensure S3 buckets should have event notifications enabled |
| [CKV_AWS_62](./rules/CKV_AWS_62.md) | HIGH (7.5/10) | Ensure no IAM policies that allow full "*-*" administrative privileges are not created |
| [CKV2_AWS_63](./rules/CKV2_AWS_63.md) | LOW (2.0/10) | Ensure Network firewall has logging configuration defined |
| [CKV_AWS_63](./rules/CKV_AWS_63.md) | HIGH (7.5/10) | Ensure no IAM policies documents allow "*" as a statement's actions |
| [CKV2_AWS_64](./rules/CKV2_AWS_64.md) | MEDIUM (5.0/10) | Ensure KMS key Policy is defined |
| [CKV_AWS_64](./rules/CKV_AWS_64.md) | LOW (2.0/10) | Ensure all data stored in the Redshift cluster is securely encrypted at rest |
| [CKV2_AWS_65](./rules/CKV2_AWS_65.md) | LOW (2.0/10) | Ensure access control lists for S3 buckets are disabled |
| [CKV_AWS_65](./rules/CKV_AWS_65.md) | LOW (2.0/10) | Ensure container insights are enabled on ECS cluster |
| [CKV2_AWS_66](./rules/CKV2_AWS_66.md) | HIGH (7.5/10) | Ensure MWAA environment is not publicly accessible |
| [CKV_AWS_66](./rules/CKV_AWS_66.md) | LOW (2.0/10) | Ensure that CloudWatch Log Group specifies retention days |
| [CKV_AWS_67](./rules/CKV_AWS_67.md) | LOW (2.0/10) | Ensure CloudTrail is enabled in all Regions |
| [CKV2_AWS_68](./rules/CKV2_AWS_68.md) | MEDIUM (5.0/10) | Ensure SageMaker notebook instance IAM policy is not overly permissive |
| [CKV_AWS_68](./rules/CKV_AWS_68.md) | LOW (2.0/10) | CloudFront Distribution should have WAF enabled |
| [CKV2_AWS_69](./rules/CKV2_AWS_69.md) | MEDIUM (5.0/10) | Ensure AWS RDS database instance configured with encryption in transit |
| [CKV_AWS_69](./rules/CKV_AWS_69.md) | CRITICAL (9/10) | Ensure Amazon MQ Broker should not have public access |
| [CKV2_AWS_70](./rules/CKV2_AWS_70.md) | MEDIUM (5.0/10) | Ensure API gateway method has authorization or API key set |
| [CKV_AWS_70](./rules/CKV_AWS_70.md) | MEDIUM (5.0/10) | Ensure S3 bucket does not allow an action with any Principal |
| [CKV2_AWS_71](./rules/CKV2_AWS_71.md) | LOW (2.0/10) | Ensure AWS ACM Certificate domain name does not include wildcards |
| [CKV_AWS_71](./rules/CKV_AWS_71.md) | LOW (2.0/10) | Ensure Redshift Cluster logging is enabled |
| [CKV2_AWS_72](./rules/CKV2_AWS_72.md) | HIGH (7/10) | Ensure AWS CloudFront origin protocol policy enforces HTTPS-only |
| [CKV_AWS_72](./rules/CKV_AWS_72.md) | LOW (2.0/10) | Ensure SQS policy does not allow ALL (*) actions. |
| [CKV2_AWS_73](./rules/CKV2_AWS_73.md) | LOW (2.0/10) | Ensure AWS SQS uses CMK not AWS default keys for encryption |
| [CKV_AWS_73](./rules/CKV_AWS_73.md) | LOW (2.0/10) | Ensure API Gateway has X-Ray Tracing enabled |
| [CKV2_AWS_74](./rules/CKV2_AWS_74.md) | LOW (2.0/10) | Ensure AWS Load Balancers use strong ciphers |
| [CKV_AWS_74](./rules/CKV_AWS_74.md) | MEDIUM (5.0/10) | Ensure DocumentDB is encrypted at rest (default is unencrypted) |
| [CKV2_AWS_75](./rules/CKV2_AWS_75.md) | MEDIUM (5.0/10) | Ensure no open CORS policy |
| [CKV_AWS_75](./rules/CKV_AWS_75.md) | LOW (2.0/10) | Ensure Global Accelerator accelerator has flow logs enabled |
| [CKV2_AWS_76](./rules/CKV2_AWS_76.md) | HIGH (7.8/10) | Ensure AWS ALB attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability |
| [CKV_AWS_76](./rules/CKV_AWS_76.md) | LOW (2.0/10) | Ensure API Gateway has Access Logging enabled |
| [CKV2_AWS_77](./rules/CKV2_AWS_77.md) | HIGH (7.8/10) | Ensure AWS API Gateway Rest API attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability |
| [CKV_AWS_77](./rules/CKV_AWS_77.md) | MEDIUM (5.0/10) | Ensure Athena Database is encrypted at rest (default is unencrypted) |
| [CKV2_AWS_78](./rules/CKV2_AWS_78.md) | HIGH (7.8/10) | Ensure AWS AppSync attached WAFv2 WebACL is configured with AMR for Log4j Vulnerability |
| [CKV_AWS_78](./rules/CKV_AWS_78.md) | MEDIUM (5.0/10) | Ensure that CodeBuild Project encryption is not disabled |
| [CKV_AWS_79](./rules/CKV_AWS_79.md) | HIGH (7.5/10) | Ensure Instance Metadata Service Version 1 is not enabled |
| [CKV_AWS_80](./rules/CKV_AWS_80.md) | MEDIUM (5.0/10) | Ensure MSK Cluster logging is enabled |
| [CKV_AWS_81](./rules/CKV_AWS_81.md) | MEDIUM (5.0/10) | Ensure MSK Cluster encryption in rest and transit is enabled |
| [CKV_AWS_82](./rules/CKV_AWS_82.md) | MEDIUM (5.0/10) | Ensure Athena Workgroup should enforce configuration to prevent client disabling encryption |
| [CKV_AWS_83](./rules/CKV_AWS_83.md) | HIGH (8/10) | Ensure Elasticsearch Domain enforces HTTPS |
| [CKV_AWS_84](./rules/CKV_AWS_84.md) | MEDIUM (5.0/10) | Ensure Elasticsearch Domain Logging is enabled |
| [CKV_AWS_85](./rules/CKV_AWS_85.md) | MEDIUM (5.0/10) | Ensure DocumentDB Logging is enabled |
| [CKV_AWS_86](./rules/CKV_AWS_86.md) | LOW (2.0/10) | Ensure CloudFront Distribution has Access Logging enabled |
| [CKV_AWS_87](./rules/CKV_AWS_87.md) | CRITICAL (9.1/10) | Redshift cluster should not be publicly accessible |
| [CKV_AWS_88](./rules/CKV_AWS_88.md) | HIGH (7.8/10) | EC2 instance should not have public IP. |
| [CKV_AWS_89](./rules/CKV_AWS_89.md) | CRITICAL (9/10) | DMS replication instance should not be publicly accessible |
| [CKV_AWS_90](./rules/CKV_AWS_90.md) | MEDIUM (5.0/10) | Ensure DocumentDB TLS is not disabled |
| [CKV_AWS_91](./rules/CKV_AWS_91.md) | LOW (2.0/10) | Ensure the ELBv2 (Application/Network) has access logging enabled |
| [CKV_AWS_92](./rules/CKV_AWS_92.md) | LOW (2.0/10) | Ensure the ELB has access logging enabled |
| [CKV_AWS_93](./rules/CKV_AWS_93.md) | MEDIUM (5.0/10) | Ensure S3 bucket policy does not lockout all but root user. |
| [CKV_AWS_94](./rules/CKV_AWS_94.md) | HIGH (7.5/10) | Ensure Glue Data Catalog Encryption is enabled |
| [CKV_AWS_95](./rules/CKV_AWS_95.md) | LOW (2.0/10) | Ensure API Gateway V2 has Access Logging enabled |
| [CKV_AWS_96](./rules/CKV_AWS_96.md) | HIGH (7.5/10) | Ensure all data stored in Aurora is securely encrypted at rest |
| [CKV_AWS_97](./rules/CKV_AWS_97.md) | HIGH (7.5/10) | Ensure Encryption in transit is enabled for EFS volumes in ECS Task definitions |
| [CKV_AWS_98](./rules/CKV_AWS_98.md) | HIGH (7.5/10) | Ensure all data stored in the Sagemaker Endpoint is securely encrypted at rest |
| [CKV_AWS_99](./rules/CKV_AWS_99.md) | HIGH (7.5/10) | Ensure Glue Security Configuration Encryption is enabled |
| [CKV_AWS_100](./rules/CKV_AWS_100.md) | HIGH (7.5/10) | Ensure AWS EKS node group does not have implicit SSH access from 0.0.0.0/0 |
| [CKV_AWS_101](./rules/CKV_AWS_101.md) | HIGH (7.5/10) | Ensure Neptune logging is enabled |
| [CKV_AWS_102](./rules/CKV_AWS_102.md) | HIGH (8/10) | Ensure Neptune Cluster instance is not publicly available |
| [CKV_AWS_103](./rules/CKV_AWS_103.md) | HIGH (7/10) | Ensure that Load Balancer Listener is using at least TLS v1.2 |
| [CKV_AWS_104](./rules/CKV_AWS_104.md) | LOW (2.0/10) | Ensure DocumentDB has audit logs enabled |
| [CKV_AWS_105](./rules/CKV_AWS_105.md) | LOW (2.0/10) | Ensure Redshift uses SSL |
| [CKV_AWS_106](./rules/CKV_AWS_106.md) | LOW (2.0/10) | Ensure EBS default encryption is enabled |
| [CKV_AWS_107](./rules/CKV_AWS_107.md) | LOW (2.0/10) | Ensure IAM policies does not allow credentials exposure |
| [CKV_AWS_108](./rules/CKV_AWS_108.md) | LOW (2.0/10) | Ensure IAM policies does not allow data exfiltration |
| [CKV_AWS_109](./rules/CKV_AWS_109.md) | LOW (2.0/10) | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| [CKV_AWS_110](./rules/CKV_AWS_110.md) | MEDIUM (5.0/10) | Ensure IAM policies does not allow privilege escalation |
| [CKV_AWS_111](./rules/CKV_AWS_111.md) | LOW (2.0/10) | Ensure IAM policies does not allow write access without constraints |
| [CKV_AWS_112](./rules/CKV_AWS_112.md) | MEDIUM (5.0/10) | Ensure Session Manager data is encrypted in transit |
| [CKV_AWS_113](./rules/CKV_AWS_113.md) | MEDIUM (5.0/10) | Ensure Session Manager logs are enabled and encrypted |
| [CKV_AWS_114](./rules/CKV_AWS_114.md) | LOW (2.0/10) | Ensure that EMR clusters with Kerberos have Kerberos Realm set |
| [CKV_AWS_115](./rules/CKV_AWS_115.md) | LOW (2.0/10) | Ensure that AWS Lambda function is configured for function-level concurrent execution limit |
| [CKV_AWS_116](./rules/CKV_AWS_116.md) | LOW (2.0/10) | Ensure that AWS Lambda function is configured for a Dead Letter Queue(DLQ) |
| [CKV_AWS_117](./rules/CKV_AWS_117.md) | LOW (2.0/10) | Ensure that AWS Lambda function is configured inside a VPC |
| [CKV_AWS_118](./rules/CKV_AWS_118.md) | LOW (2.0/10) | Ensure that enhanced monitoring is enabled for Amazon RDS instances |
| [CKV_AWS_119](./rules/CKV_AWS_119.md) | LOW (2.0/10) | Ensure DynamoDB Tables are encrypted using a KMS Customer Managed CMK |
| [CKV_AWS_120](./rules/CKV_AWS_120.md) | LOW (2.0/10) | Ensure API Gateway caching is enabled |
| [CKV_AWS_121](./rules/CKV_AWS_121.md) | MEDIUM (5.0/10) | Ensure AWS Config is enabled in all regions |
| [CKV_AWS_122](./rules/CKV_AWS_122.md) | LOW (2.0/10) | Ensure that direct internet access is disabled for an Amazon SageMaker Notebook Instance |
| [CKV_AWS_123](./rules/CKV_AWS_123.md) | LOW (2.0/10) | Ensure that VPC Endpoint Service is configured for Manual Acceptance |
| [CKV_AWS_124](./rules/CKV_AWS_124.md) | LOW (2.0/10) | Ensure that CloudFormation stacks are sending event notifications to an SNS topic |
| [CKV_AWS_126](./rules/CKV_AWS_126.md) | MEDIUM (5.0/10) | Ensure that detailed monitoring is enabled for EC2 instances |
| [CKV_AWS_127](./rules/CKV_AWS_127.md) | HIGH (7.5/10) | Ensure that Elastic Load Balancer(s) uses SSL certificates provided by AWS Certificate Manager |
| [CKV_AWS_129](./rules/CKV_AWS_129.md) | LOW (2.0/10) | Ensure that respective logs of Amazon Relational Database Service (Amazon RDS) are enabled |
| [CKV_AWS_130](./rules/CKV_AWS_130.md) | HIGH (7/10) | Ensure VPC subnets do not assign public IP by default |
| [CKV_AWS_131](./rules/CKV_AWS_131.md) | MEDIUM (5.0/10) | Ensure that ALB drops HTTP headers |
| [CKV_AWS_133](./rules/CKV_AWS_133.md) | LOW (2.0/10) | Ensure that RDS instances has backup policy |
| [CKV_AWS_134](./rules/CKV_AWS_134.md) | LOW (2.0/10) | Ensure that Amazon ElastiCache Redis clusters have automatic backup turned on |
| [CKV_AWS_135](./rules/CKV_AWS_135.md) | LOW (2.0/10) | Ensure that EC2 is EBS optimized |
| [CKV_AWS_136](./rules/CKV_AWS_136.md) | LOW (2.0/10) | Ensure that ECR repositories are encrypted using KMS |
| [CKV_AWS_137](./rules/CKV_AWS_137.md) | CRITICAL (9/10) | Ensure that Elasticsearch is configured inside a VPC |
| [CKV_AWS_138](./rules/CKV_AWS_138.md) | LOW (2.0/10) | Ensure that ELB is cross-zone-load-balancing enabled |
| [CKV_AWS_139](./rules/CKV_AWS_139.md) | LOW (2.0/10) | Ensure that RDS clusters have deletion protection enabled |
| [CKV_AWS_140](./rules/CKV_AWS_140.md) | LOW (2.0/10) | Ensure that RDS global clusters are encrypted |
| [CKV_AWS_141](./rules/CKV_AWS_141.md) | LOW (2.0/10) | Ensured that Redshift cluster allowing version upgrade by default |
| [CKV_AWS_142](./rules/CKV_AWS_142.md) | LOW (2.0/10) | Ensure that Redshift cluster is encrypted by KMS |
| [CKV_AWS_143](./rules/CKV_AWS_143.md) | LOW (2.0/10) | Ensure that S3 bucket has lock configuration enabled by default |
| [CKV_AWS_144](./rules/CKV_AWS_144.md) | LOW (2.0/10) | Ensure that S3 bucket has cross-region replication enabled |
| [CKV_AWS_145](./rules/CKV_AWS_145.md) | LOW (2.0/10) | Ensure that S3 buckets are encrypted with KMS by default |
| [CKV_AWS_146](./rules/CKV_AWS_146.md) | LOW (2.0/10) | Ensure that RDS database cluster snapshot is encrypted |
| [CKV_AWS_147](./rules/CKV_AWS_147.md) | MEDIUM (5.0/10) | Ensure that CodeBuild projects are encrypted using CMK |
| [CKV_AWS_148](./rules/CKV_AWS_148.md) | LOW (2.0/10) | Ensure no default VPC is planned to be provisioned |
| [CKV_AWS_149](./rules/CKV_AWS_149.md) | LOW (2.0/10) | Ensure that Secrets Manager secret is encrypted using KMS CMK |
| [CKV_AWS_150](./rules/CKV_AWS_150.md) | LOW (2.0/10) | Ensure that Load Balancer has deletion protection enabled |
| [CKV_AWS_152](./rules/CKV_AWS_152.md) | LOW (2.0/10) | Ensure that Load Balancer (Network/Gateway) has cross-zone load balancing enabled |
| [CKV_AWS_153](./rules/CKV_AWS_153.md) | LOW (2.0/10) | Autoscaling groups should supply tags to launch configurations |
| [CKV_AWS_154](./rules/CKV_AWS_154.md) | HIGH (7.5/10) | Ensure Redshift is not deployed outside of a VPC |
| [CKV_AWS_155](./rules/CKV_AWS_155.md) | MEDIUM (5.0/10) | Ensure that Workspace user volumes are encrypted |
| [CKV_AWS_156](./rules/CKV_AWS_156.md) | MEDIUM (5.0/10) | Ensure that Workspace root volumes are encrypted |
| [CKV_AWS_157](./rules/CKV_AWS_157.md) | LOW (2.0/10) | Ensure that RDS instances have Multi-AZ enabled |
| [CKV_AWS_158](./rules/CKV_AWS_158.md) | LOW (2.0/10) | Ensure that CloudWatch Log Group is encrypted by KMS |
| [CKV_AWS_159](./rules/CKV_AWS_159.md) | MEDIUM (5.0/10) | Ensure that Athena Workgroup is encrypted |
| [CKV_AWS_160](./rules/CKV_AWS_160.md) | MEDIUM (5.0/10) | Ensure that Timestream database is encrypted with KMS CMK |
| [CKV_AWS_161](./rules/CKV_AWS_161.md) | MEDIUM (5.0/10) | Ensure RDS database has IAM authentication enabled |
| [CKV_AWS_162](./rules/CKV_AWS_162.md) | LOW (2.0/10) | Ensure RDS cluster has IAM authentication enabled |
| [CKV_AWS_163](./rules/CKV_AWS_163.md) | HIGH (7.5/10) | Ensure ECR image scanning on push is enabled |
| [CKV_AWS_164](./rules/CKV_AWS_164.md) | HIGH (7.5/10) | Ensure Transfer Server is not exposed publicly |
| [CKV_AWS_165](./rules/CKV_AWS_165.md) | MEDIUM (5.0/10) | Ensure DynamoDB point in time recovery (backup) is enabled for global tables |
| [CKV_AWS_166](./rules/CKV_AWS_166.md) | MEDIUM (5.0/10) | Ensure Backup Vault is encrypted at rest using KMS CMK |
| [CKV_AWS_167](./rules/CKV_AWS_167.md) | MEDIUM (5.0/10) | Ensure Glacier Vault access policy is not public by only allowing specific services or principals to access it |
| [CKV_AWS_168](./rules/CKV_AWS_168.md) | HIGH (7.5/10) | Ensure SQS queue policy is not public by only allowing specific services or principals to access it |
| [CKV_AWS_169](./rules/CKV_AWS_169.md) | MEDIUM (5.0/10) | Ensure SNS topic policy is not public by only allowing specific services or principals to access it |
| [CKV_AWS_170](./rules/CKV_AWS_170.md) | MEDIUM (5.0/10) | Ensure QLDB ledger permissions mode is set to STANDARD |
| [CKV_AWS_171](./rules/CKV_AWS_171.md) | LOW (2.0/10) | Ensure EMR Cluster security configuration encryption is using SSE-KMS |
| [CKV_AWS_172](./rules/CKV_AWS_172.md) | LOW (2.0/10) | Ensure QLDB ledger has deletion protection enabled |
| [CKV_AWS_173](./rules/CKV_AWS_173.md) | LOW (2.0/10) | Check encryption settings for Lambda environmental variable |
| [CKV_AWS_174](./rules/CKV_AWS_174.md) | HIGH (7.5/10) | Verify CloudFront Distribution Viewer Certificate is using TLS v1.2 or higher |
| [CKV_AWS_175](./rules/CKV_AWS_175.md) | LOW (2.0/10) | Ensure WAF has associated rules |
| [CKV_AWS_176](./rules/CKV_AWS_176.md) | LOW (2.0/10) | Ensure Logging is enabled for WAF Web Access Control Lists |
| [CKV_AWS_177](./rules/CKV_AWS_177.md) | LOW (2.0/10) | Ensure Kinesis Video Stream is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_178](./rules/CKV_AWS_178.md) | LOW (2.0/10) | Ensure fx ontap file system is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_179](./rules/CKV_AWS_179.md) | LOW (2.0/10) | Ensure FSX Windows filesystem is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_180](./rules/CKV_AWS_180.md) | LOW (2.0/10) | Ensure Image Builder component is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_181](./rules/CKV_AWS_181.md) | LOW (2.0/10) | Ensure S3 Object Copy is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_182](./rules/CKV_AWS_182.md) | LOW (2.0/10) | Ensure DocumentDB is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_183](./rules/CKV_AWS_183.md) | LOW (2.0/10) | Ensure EBS Snapshot Copy is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_184](./rules/CKV_AWS_184.md) | LOW (2.0/10) | Ensure resource is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_185](./rules/CKV_AWS_185.md) | LOW (2.0/10) | Ensure Kinesis Stream is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_186](./rules/CKV_AWS_186.md) | LOW (2.0/10) | Ensure S3 bucket Object is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_187](./rules/CKV_AWS_187.md) | LOW (2.0/10) | Ensure Sagemaker domain and notebook instance are encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_189](./rules/CKV_AWS_189.md) | LOW (2.0/10) | Ensure EBS Volume is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_190](./rules/CKV_AWS_190.md) | LOW (2.0/10) | Ensure lustre file systems is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_191](./rules/CKV_AWS_191.md) | LOW (2.0/10) | Ensure ElastiCache replication group is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_192](./rules/CKV_AWS_192.md) | HIGH (7.5/10) | Ensure WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell |
| [CKV_AWS_193](./rules/CKV_AWS_193.md) | LOW (2.0/10) | Ensure AppSync has Logging enabled |
| [CKV_AWS_194](./rules/CKV_AWS_194.md) | LOW (2.0/10) | Ensure AppSync has Field-Level logs enabled |
| [CKV_AWS_195](./rules/CKV_AWS_195.md) | LOW (2.0/10) | Ensure Glue component has a security configuration associated |
| [CKV_AWS_196](./rules/CKV_AWS_196.md) | MEDIUM (5/10) | Ensure no aws_elasticache_security_group resources exist |
| [CKV_AWS_197](./rules/CKV_AWS_197.md) | LOW (2.0/10) | Ensure MQ Broker Audit logging is enabled |
| [CKV_AWS_198](./rules/CKV_AWS_198.md) | LOW (2.0/10) | Ensure no aws_db_security_group resources exist |
| [CKV_AWS_199](./rules/CKV_AWS_199.md) | LOW (2.0/10) | Ensure Image Builder Distribution Configuration encrypts AMI's using KMS - a customer managed Key (CMK) |
| [CKV_AWS_200](./rules/CKV_AWS_200.md) | LOW (2.0/10) | Ensure that Image Recipe EBS Disk are encrypted with CMK |
| [CKV_AWS_201](./rules/CKV_AWS_201.md) | LOW (2.0/10) | Ensure MemoryDB is encrypted at rest using KMS CMKs |
| [CKV_AWS_202](./rules/CKV_AWS_202.md) | LOW (2.0/10) | Ensure MemoryDB data is encrypted in transit |
| [CKV_AWS_203](./rules/CKV_AWS_203.md) | LOW (2.0/10) | Ensure resource is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_204](./rules/CKV_AWS_204.md) | LOW (2.0/10) | Ensure AMIs are encrypted using KMS CMKs |
| [CKV_AWS_205](./rules/CKV_AWS_205.md) | LOW (2.0/10) | Ensure to Limit AMI launch Permissions |
| [CKV_AWS_206](./rules/CKV_AWS_206.md) | HIGH (7/10) | Ensure API Gateway Domain uses a modern security Policy |
| [CKV_AWS_207](./rules/CKV_AWS_207.md) | LOW (2.0/10) | Ensure MQ Broker minor version updates are enabled |
| [CKV_AWS_208](./rules/CKV_AWS_208.md) | LOW (2.0/10) | Ensure MQ Broker version is current |
| [CKV_AWS_209](./rules/CKV_AWS_209.md) | LOW (2.0/10) | Ensure MQ broker encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_210](./rules/CKV_AWS_210.md) | LOW (2.0/10) | Batch job does not define a privileged container |
| [CKV_AWS_211](./rules/CKV_AWS_211.md) | LOW (2.0/10) | Ensure RDS uses a modern CaCert |
| [CKV_AWS_212](./rules/CKV_AWS_212.md) | LOW (2.0/10) | Ensure DMS replication instance is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_213](./rules/CKV_AWS_213.md) | LOW (2.0/10) | Ensure ELB Policy uses only secure protocols |
| [CKV_AWS_214](./rules/CKV_AWS_214.md) | LOW (2.0/10) | Ensure AppSync API Cache is encrypted at rest |
| [CKV_AWS_215](./rules/CKV_AWS_215.md) | LOW (2.0/10) | Ensure AppSync API Cache is encrypted in transit |
| [CKV_AWS_216](./rules/CKV_AWS_216.md) | LOW (2.0/10) | Ensure CloudFront distribution is enabled |
| [CKV_AWS_217](./rules/CKV_AWS_217.md) | LOW (2.0/10) | Ensure Create before destroy for API deployments |
| [CKV_AWS_218](./rules/CKV_AWS_218.md) | HIGH (7/10) | Ensure that CloudSearch is using latest TLS |
| [CKV_AWS_219](./rules/CKV_AWS_219.md) | LOW (2.0/10) | Ensure CodePipeline Artifact store is using a KMS CMK |
| [CKV_AWS_220](./rules/CKV_AWS_220.md) | HIGH (7.5/10) | Ensure that CloudSearch is using https |
| [CKV_AWS_221](./rules/CKV_AWS_221.md) | LOW (2.0/10) | Ensure CodeArtifact Domain is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_222](./rules/CKV_AWS_222.md) | LOW (2.0/10) | Ensure DMS replication instance gets all minor upgrade automatically |
| [CKV_AWS_223](./rules/CKV_AWS_223.md) | LOW (2.0/10) | Ensure ECS Cluster enables logging of ECS Exec |
| [CKV_AWS_224](./rules/CKV_AWS_224.md) | LOW (2.0/10) | Ensure ECS Cluster logging is enabled and client to container communication uses CMK |
| [CKV_AWS_225](./rules/CKV_AWS_225.md) | LOW (2.0/10) | Ensure API Gateway method setting caching is enabled |
| [CKV_AWS_226](./rules/CKV_AWS_226.md) | LOW (2.0/10) | Ensure DB instance gets all minor upgrades automatically |
| [CKV_AWS_227](./rules/CKV_AWS_227.md) | LOW (2.0/10) | Ensure KMS key is enabled |
| [CKV_AWS_228](./rules/CKV_AWS_228.md) | HIGH (7.5/10) | Verify Elasticsearch domain is using an up to date TLS policy |
| [CKV_AWS_229](./rules/CKV_AWS_229.md) | HIGH (7.3/10) | Ensure no NACL allow ingress from 0.0.0.0:0 to port 21 |
| [CKV_AWS_230](./rules/CKV_AWS_230.md) | HIGH (7.2/10) | Ensure no NACL allow ingress from 0.0.0.0:0 to port 20 |
| [CKV_AWS_231](./rules/CKV_AWS_231.md) | CRITICAL (9.2/10) | Ensure no NACL allow ingress from 0.0.0.0:0 to port 3389 |
| [CKV_AWS_232](./rules/CKV_AWS_232.md) | CRITICAL (9.2/10) | Ensure no NACL allow ingress from 0.0.0.0:0 to port 22 |
| [CKV_AWS_233](./rules/CKV_AWS_233.md) | LOW (2.0/10) | Ensure Create before destroy for ACM certificates |
| [CKV_AWS_234](./rules/CKV_AWS_234.md) | LOW (2.0/10) | Verify logging preference for ACM certificates |
| [CKV_AWS_235](./rules/CKV_AWS_235.md) | LOW (2.0/10) | Ensure that copied AMIs are encrypted |
| [CKV_AWS_236](./rules/CKV_AWS_236.md) | LOW (2.0/10) | Ensure AMI copying uses a CMK |
| [CKV_AWS_237](./rules/CKV_AWS_237.md) | LOW (2.0/10) | Ensure Create before destroy for API Gateway |
| [CKV_AWS_238](./rules/CKV_AWS_238.md) | LOW (2.0/10) | Ensure that GuardDuty detector is enabled |
| [CKV_AWS_239](./rules/CKV_AWS_239.md) | HIGH (7/10) | Ensure DAX cluster endpoint is using TLS |
| [CKV_AWS_240](./rules/CKV_AWS_240.md) | LOW (2.0/10) | Ensure Kinesis Firehose delivery stream is encrypted |
| [CKV_AWS_241](./rules/CKV_AWS_241.md) | LOW (2.0/10) | Ensure that Kinesis Firehose Delivery Streams are encrypted with CMK |
| [CKV_AWS_242](./rules/CKV_AWS_242.md) | LOW (2.0/10) | Ensure MWAA environment has scheduler logs enabled |
| [CKV_AWS_243](./rules/CKV_AWS_243.md) | LOW (2.0/10) | Ensure MWAA environment has worker logs enabled |
| [CKV_AWS_244](./rules/CKV_AWS_244.md) | LOW (2.0/10) | Ensure MWAA environment has webserver logs enabled |
| [CKV_AWS_245](./rules/CKV_AWS_245.md) | LOW (2.0/10) | Ensure replicated backups are encrypted at rest using KMS CMKs |
| [CKV_AWS_246](./rules/CKV_AWS_246.md) | LOW (2.0/10) | Ensure RDS Cluster activity streams are encrypted using KMS CMKs |
| [CKV_AWS_247](./rules/CKV_AWS_247.md) | LOW (2.0/10) | Ensure all data stored in the Elasticsearch is encrypted with a CMK |
| [CKV_AWS_248](./rules/CKV_AWS_248.md) | LOW (2.0/10) | Ensure that Elasticsearch is not using the default Security Group |
| [CKV_AWS_249](./rules/CKV_AWS_249.md) | LOW (2.0/10) | Ensure that the Execution Role ARN and the Task Role ARN are different in ECS Task definitions |
| [CKV_AWS_250](./rules/CKV_AWS_250.md) | MEDIUM (5.0/10) | Ensure that RDS PostgreSQL instances use a non vulnerable version with the log_fdw extension |
| [CKV_AWS_251](./rules/CKV_AWS_251.md) | LOW (2.0/10) | Ensure CloudTrail logging is enabled |
| [CKV_AWS_252](./rules/CKV_AWS_252.md) | LOW (2.0/10) | Ensure CloudTrail defines an SNS Topic |
| [CKV_AWS_253](./rules/CKV_AWS_253.md) | LOW (2.0/10) | Ensure DLM cross region events are encrypted |
| [CKV_AWS_254](./rules/CKV_AWS_254.md) | LOW (2.0/10) | Ensure DLM cross region events are encrypted with Customer Managed Key |
| [CKV_AWS_255](./rules/CKV_AWS_255.md) | LOW (2.0/10) | Ensure DLM cross region schedules are encrypted |
| [CKV_AWS_256](./rules/CKV_AWS_256.md) | LOW (2.0/10) | Ensure DLM cross region schedules are encrypted using a Customer Managed Key |
| [CKV_AWS_257](./rules/CKV_AWS_257.md) | LOW (2.0/10) | Ensure CodeCommit branch changes have at least 2 approvals |
| [CKV_AWS_258](./rules/CKV_AWS_258.md) | MEDIUM (5.0/10) | Ensure that Lambda function URLs AuthType is not None |
| [CKV_AWS_259](./rules/CKV_AWS_259.md) | MEDIUM (6/10) | Ensure CloudFront response header policy enforces Strict Transport Security |
| [CKV_AWS_260](./rules/CKV_AWS_260.md) | MEDIUM (5/10) | Ensure no security groups allow ingress from 0.0.0.0:0 to port 80 |
| [CKV_AWS_261](./rules/CKV_AWS_261.md) | LOW (2.0/10) | Ensure HTTP HTTPS Target group defines Healthcheck |
| [CKV_AWS_262](./rules/CKV_AWS_262.md) | LOW (2.0/10) | Ensure Kendra index Server side encryption uses CMK |
| [CKV_AWS_263](./rules/CKV_AWS_263.md) | LOW (2.0/10) | Ensure AppFlow flow uses CMK |
| [CKV_AWS_264](./rules/CKV_AWS_264.md) | LOW (2.0/10) | Ensure AppFlow connector profile uses CMK |
| [CKV_AWS_265](./rules/CKV_AWS_265.md) | LOW (2.0/10) | Ensure Keyspaces Table uses CMK |
| [CKV_AWS_266](./rules/CKV_AWS_266.md) | LOW (2.0/10) | Ensure DB Snapshot copy uses CMK |
| [CKV_AWS_267](./rules/CKV_AWS_267.md) | HIGH (7.5/10) | Ensure that Comprehend Entity Recognizer's model is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_268](./rules/CKV_AWS_268.md) | HIGH (7.5/10) | Ensure that Comprehend Entity Recognizer's volume is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_269](./rules/CKV_AWS_269.md) | MEDIUM (5.0/10) | Ensure Connect Instance Kinesis Video Stream Storage Config uses CMK |
| [CKV_AWS_270](./rules/CKV_AWS_270.md) | HIGH (7.5/10) | Ensure Connect Instance S3 Storage Config uses CMK |
| [CKV_AWS_271](./rules/CKV_AWS_271.md) | HIGH (7.5/10) | Ensure DynamoDB table replica KMS encryption uses CMK |
| [CKV_AWS_272](./rules/CKV_AWS_272.md) | HIGH (7.5/10) | Ensure AWS Lambda function is configured to validate code-signing |
| [CKV_AWS_273](./rules/CKV_AWS_273.md) | LOW (2.0/10) | Ensure access is controlled through SSO and not AWS IAM defined users |
| [CKV_AWS_274](./rules/CKV_AWS_274.md) | HIGH (7.5/10) | Disallow IAM roles, users, and groups from using the AWS AdministratorAccess policy |
| [CKV_AWS_275](./rules/CKV_AWS_275.md) | HIGH (7.5/10) | Disallow policies from using the AWS AdministratorAccess policy |
| [CKV_AWS_276](./rules/CKV_AWS_276.md) | LOW (2.0/10) | Ensure Data Trace is not enabled in API Gateway Method Settings |
| [CKV_AWS_277](./rules/CKV_AWS_277.md) | CRITICAL (9.8/10) | Ensure no security groups allow ingress from 0.0.0.0:0 to port -1 |
| [CKV_AWS_278](./rules/CKV_AWS_278.md) | HIGH (7.5/10) | Ensure MemoryDB snapshot is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_279](./rules/CKV_AWS_279.md) | HIGH (7.5/10) | Ensure Neptune snapshot is securely encrypted |
| [CKV_AWS_280](./rules/CKV_AWS_280.md) | HIGH (7.5/10) | Ensure Neptune snapshot is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_281](./rules/CKV_AWS_281.md) | HIGH (7.5/10) | Ensure RedShift snapshot copy is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_282](./rules/CKV_AWS_282.md) | HIGH (7.5/10) | Ensure that Redshift Serverless namespace is encrypted by KMS using a customer managed key (CMK) |
| [CKV_AWS_283](./rules/CKV_AWS_283.md) | HIGH (7.5/10) | Ensure no IAM policies documents allow ALL or any AWS principal permissions to the resource |
| [CKV_AWS_284](./rules/CKV_AWS_284.md) | LOW (2.0/10) | Ensure State Machine has X-Ray tracing enabled |
| [CKV_AWS_285](./rules/CKV_AWS_285.md) | MEDIUM (5.0/10) | Ensure State Machine has execution history logging enabled |
| [CKV_AWS_286](./rules/CKV_AWS_286.md) | MEDIUM (5.0/10) | Ensure IAM policies does not allow privilege escalation |
| [CKV_AWS_287](./rules/CKV_AWS_287.md) | HIGH (7.5/10) | Ensure IAM policies does not allow credentials exposure |
| [CKV_AWS_288](./rules/CKV_AWS_288.md) | HIGH (7.5/10) | Ensure IAM policies does not allow data exfiltration |
| [CKV_AWS_289](./rules/CKV_AWS_289.md) | HIGH (7.5/10) | Ensure IAM policies does not allow permissions management / resource exposure without constraints |
| [CKV_AWS_290](./rules/CKV_AWS_290.md) | HIGH (7.5/10) | Ensure IAM policies does not allow write access without constraints |
| [CKV_AWS_291](./rules/CKV_AWS_291.md) | HIGH (7.5/10) | Ensure MSK nodes are private |
| [CKV_AWS_292](./rules/CKV_AWS_292.md) | HIGH (7.5/10) | Ensure DocumentDB Global Cluster is encrypted at rest (default is unencrypted) |
| [CKV_AWS_293](./rules/CKV_AWS_293.md) | MEDIUM (5.0/10) | Ensure that AWS database instances have deletion protection enabled |
| [CKV_AWS_294](./rules/CKV_AWS_294.md) | LOW (2.0/10) | Ensure CloudTrail Event Data Store uses CMK |
| [CKV_AWS_295](./rules/CKV_AWS_295.md) | HIGH (7.5/10) | Ensure DataSync Location Object Storage doesn't expose secrets |
| [CKV_AWS_296](./rules/CKV_AWS_296.md) | HIGH (7.5/10) | Ensure DMS endpoint uses Customer Managed Key (CMK) |
| [CKV_AWS_297](./rules/CKV_AWS_297.md) | HIGH (7.5/10) | Ensure EventBridge Scheduler Schedule uses Customer Managed Key (CMK) |
| [CKV_AWS_298](./rules/CKV_AWS_298.md) | HIGH (7.5/10) | Ensure DMS S3 uses Customer Managed Key (CMK) |
| [CKV_AWS_300](./rules/CKV_AWS_300.md) | MEDIUM (5.0/10) | Ensure S3 lifecycle configuration sets period for aborting failed uploads |
| [CKV_AWS_301](./rules/CKV_AWS_301.md) | LOW (2.0/10) | Ensure that AWS Lambda function is not publicly accessible |
| [CKV_AWS_302](./rules/CKV_AWS_302.md) | CRITICAL (9/10) | Ensure DB Snapshots are not Public |
| [CKV_AWS_303](./rules/CKV_AWS_303.md) | HIGH (7.5/10) | Ensure SSM documents are not Public |
| [CKV_AWS_304](./rules/CKV_AWS_304.md) | HIGH (7.5/10) | Ensure Secrets Manager secrets should be rotated within 90 days |
| [CKV_AWS_305](./rules/CKV_AWS_305.md) | MEDIUM (4.5/10) | Ensure CloudFront distribution has a default root object configured |
| [CKV_AWS_306](./rules/CKV_AWS_306.md) | HIGH (7/10) | Ensure SageMaker notebook instances should be launched into a custom VPC |
| [CKV_AWS_307](./rules/CKV_AWS_307.md) | LOW (2.0/10) | Ensure SageMaker Users should not have root access to SageMaker notebook instances |
| [CKV_AWS_308](./rules/CKV_AWS_308.md) | HIGH (7.5/10) | Ensure API Gateway method setting caching is set to encrypted |
| [CKV_AWS_309](./rules/CKV_AWS_309.md) | MEDIUM (5.0/10) | Ensure API GatewayV2 routes specify an authorization type |
| [CKV_AWS_310](./rules/CKV_AWS_310.md) | MEDIUM (4.5/10) | Ensure CloudFront distributions should have origin failover configured |
| [CKV_AWS_311](./rules/CKV_AWS_311.md) | HIGH (7.5/10) | Ensure that CodeBuild S3 logs are encrypted |
| [CKV_AWS_312](./rules/CKV_AWS_312.md) | HIGH (7.5/10) | Ensure Elastic Beanstalk environments have enhanced health reporting enabled |
| [CKV_AWS_313](./rules/CKV_AWS_313.md) | LOW (2.0/10) | Ensure RDS cluster configured to copy tags to snapshots |
| [CKV_AWS_314](./rules/CKV_AWS_314.md) | LOW (2.0/10) | Ensure CodeBuild project environments have a logging configuration |
| [CKV_AWS_315](./rules/CKV_AWS_315.md) | MEDIUM (5.0/10) | Ensure EC2 Auto Scaling groups use EC2 launch templates |
| [CKV_AWS_316](./rules/CKV_AWS_316.md) | MEDIUM (5.0/10) | Ensure CodeBuild project environments do not have privileged mode enabled |
| [CKV_AWS_317](./rules/CKV_AWS_317.md) | MEDIUM (5.0/10) | Ensure Elasticsearch Domain Audit Logging is enabled |
| [CKV_AWS_318](./rules/CKV_AWS_318.md) | MEDIUM (5.0/10) | Ensure Elasticsearch domains are configured with at least three dedicated master nodes for HA |
| [CKV_AWS_319](./rules/CKV_AWS_319.md) | MEDIUM (5.0/10) | Ensure that CloudWatch alarm actions are enabled |
| [CKV_AWS_320](./rules/CKV_AWS_320.md) | MEDIUM (5.0/10) | Ensure Redshift clusters do not use the default database name |
| [CKV_AWS_321](./rules/CKV_AWS_321.md) | MEDIUM (5.0/10) | Ensure Redshift clusters use enhanced VPC routing |
| [CKV_AWS_322](./rules/CKV_AWS_322.md) | LOW (2.0/10) | Ensure ElastiCache for Redis cache clusters have auto minor version upgrades enabled |
| [CKV_AWS_323](./rules/CKV_AWS_323.md) | MEDIUM (4.5/10) | Ensure ElastiCache clusters do not use the default subnet group |
| [CKV_AWS_324](./rules/CKV_AWS_324.md) | MEDIUM (5.0/10) | Ensure that RDS Cluster log capture is enabled |
| [CKV_AWS_325](./rules/CKV_AWS_325.md) | LOW (2.0/10) | Ensure that RDS Cluster audit logging is enabled for MySQL engine |
| [CKV_AWS_326](./rules/CKV_AWS_326.md) | MEDIUM (5.0/10) | Ensure that RDS Aurora Clusters have backtracking enabled |
| [CKV_AWS_327](./rules/CKV_AWS_327.md) | LOW (2.0/10) | Ensure RDS Clusters are encrypted using KMS CMKs |
| [CKV_AWS_328](./rules/CKV_AWS_328.md) | HIGH (7.5/10) | Ensure that ALB is configured with defensive or strictest desync mitigation mode |
| [CKV_AWS_329](./rules/CKV_AWS_329.md) | HIGH (7.5/10) | EFS access points should enforce a root directory |
| [CKV_AWS_330](./rules/CKV_AWS_330.md) | MEDIUM (5.0/10) | EFS access points should enforce a user identity |
| [CKV_AWS_331](./rules/CKV_AWS_331.md) | HIGH (7/10) | Ensure Transit Gateways do not automatically accept VPC attachment requests |
| [CKV_AWS_332](./rules/CKV_AWS_332.md) | MEDIUM (5.0/10) | Ensure ECS Fargate services run on the latest Fargate platform version |
| [CKV_AWS_333](./rules/CKV_AWS_333.md) | LOW (2.0/10) | Ensure ECS services do not have public IP addresses assigned to them automatically |
| [CKV_AWS_334](./rules/CKV_AWS_334.md) | MEDIUM (5.0/10) | Ensure ECS containers should run as non-privileged |
| [CKV_AWS_335](./rules/CKV_AWS_335.md) | MEDIUM (5.0/10) | Ensure ECS task definitions should not share the host's process namespace |
| [CKV_AWS_336](./rules/CKV_AWS_336.md) | LOW (2.0/10) | Ensure ECS containers are limited to read-only access to root filesystems |
| [CKV_AWS_337](./rules/CKV_AWS_337.md) | HIGH (7.5/10) | Ensure SSM parameters are using KMS CMK |
| [CKV_AWS_338](./rules/CKV_AWS_338.md) | LOW (2.0/10) | Ensure CloudWatch log groups retains logs for at least 1 year |
| [CKV_AWS_339](./rules/CKV_AWS_339.md) | HIGH (7.5/10) | Ensure EKS clusters run on a supported Kubernetes version |
| [CKV_AWS_340](./rules/CKV_AWS_340.md) | LOW (2.0/10) | Ensure Elastic Beanstalk managed platform updates are enabled |
| [CKV_AWS_341](./rules/CKV_AWS_341.md) | MEDIUM (5.0/10) | Ensure Launch template should not have a metadata response hop limit greater than 1 |
| [CKV_AWS_342](./rules/CKV_AWS_342.md) | MEDIUM (5.5/10) | Ensure WAF rule has any actions |
| [CKV_AWS_343](./rules/CKV_AWS_343.md) | HIGH (7.5/10) | Ensure Amazon Redshift clusters should have automatic snapshots enabled |
| [CKV_AWS_344](./rules/CKV_AWS_344.md) | HIGH (7.5/10) | Ensure that Network firewalls have deletion protection enabled |
| [CKV_AWS_345](./rules/CKV_AWS_345.md) | HIGH (7.5/10) | Ensure that Network firewall encryption is via a CMK |
| [CKV_AWS_346](./rules/CKV_AWS_346.md) | HIGH (7.5/10) | Ensure Network Firewall Policy defines an encryption configuration that uses a customer managed Key (CMK) |
| [CKV_AWS_347](./rules/CKV_AWS_347.md) | HIGH (7.5/10) | Ensure Neptune is encrypted by KMS using a customer managed Key (CMK) |
| [CKV_AWS_348](./rules/CKV_AWS_348.md) | HIGH (7.5/10) | Ensure IAM root user does not have Access keys |
| [CKV_AWS_349](./rules/CKV_AWS_349.md) | LOW (2.0/10) | Ensure EMR Cluster security configuration encrypts local disks |
| [CKV_AWS_350](./rules/CKV_AWS_350.md) | HIGH (7.5/10) | Ensure EMR Cluster security configuration encrypts EBS disks |
| [CKV_AWS_351](./rules/CKV_AWS_351.md) | LOW (2.0/10) | Ensure EMR Cluster security configuration encrypts InTransit |
| [CKV_AWS_352](./rules/CKV_AWS_352.md) | HIGH (7.5/10) | Ensure NACL ingress does not allow all Ports |
| [CKV_AWS_353](./rules/CKV_AWS_353.md) | LOW (2.0/10) | Ensure that RDS instances have performance insights enabled |
| [CKV_AWS_354](./rules/CKV_AWS_354.md) | HIGH (7.5/10) | Ensure RDS Performance Insights are encrypted using KMS CMKs |
| [CKV_AWS_355](./rules/CKV_AWS_355.md) | HIGH (7.5/10) | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |
| [CKV_AWS_356](./rules/CKV_AWS_356.md) | HIGH (7.5/10) | Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions |
| [CKV_AWS_357](./rules/CKV_AWS_357.md) | HIGH (7.5/10) | Ensure Transfer Server allows only secure protocols |
| [CKV_AWS_358](./rules/CKV_AWS_358.md) | HIGH (7.5/10) | Ensure AWS GitHub Actions OIDC authorization policies only allow safe claims and claim order |
| [CKV_AWS_359](./rules/CKV_AWS_359.md) | LOW (2.0/10) | Neptune DB clusters should have IAM database authentication enabled |
| [CKV_AWS_360](./rules/CKV_AWS_360.md) | LOW (2.0/10) | Ensure DocumentDB has an adequate backup retention period |
| [CKV_AWS_361](./rules/CKV_AWS_361.md) | LOW (2.0/10) | Ensure that Neptune DB cluster has automated backups enabled with adequate retention |
| [CKV_AWS_362](./rules/CKV_AWS_362.md) | LOW (2.0/10) | Neptune DB clusters should be configured to copy tags to snapshots |
| [CKV_AWS_363](./rules/CKV_AWS_363.md) | MEDIUM (5.0/10) | Ensure Lambda Runtime is not deprecated |
| [CKV_AWS_364](./rules/CKV_AWS_364.md) | HIGH (7.5/10) | Ensure that AWS Lambda function permissions delegated to AWS services are limited by SourceArn or SourceAccount |
| [CKV_AWS_365](./rules/CKV_AWS_365.md) | MEDIUM (5.5/10) | Ensure SES Configuration Set enforces TLS usage |
| [CKV_AWS_366](./rules/CKV_AWS_366.md) | MEDIUM (5.0/10) | Ensure AWS Cognito identity pool does not allow unauthenticated guest access |
| [CKV_AWS_367](./rules/CKV_AWS_367.md) | LOW (2.0/10) | Ensure Amazon Sagemaker Data Quality Job uses KMS to encrypt model artifacts |
| [CKV_AWS_368](./rules/CKV_AWS_368.md) | LOW (2.0/10) | Ensure Amazon Sagemaker Data Quality Job uses KMS to encrypt data on attached storage volume |
| [CKV_AWS_369](./rules/CKV_AWS_369.md) | LOW (2.0/10) | Ensure Amazon Sagemaker Data Quality Job encrypts all communications between instances used for monitoring jobs |
| [CKV_AWS_370](./rules/CKV_AWS_370.md) | MEDIUM (5.0/10) | Ensure Amazon SageMaker model uses network isolation |
| [CKV_AWS_371](./rules/CKV_AWS_371.md) | MEDIUM (5.0/10) | Ensure Amazon SageMaker Notebook Instance only allows for IMDSv2 |
| [CKV_AWS_372](./rules/CKV_AWS_372.md) | LOW (2.0/10) | Ensure Amazon SageMaker Flow Definition uses KMS for output configurations |
| [CKV_AWS_373](./rules/CKV_AWS_373.md) | MEDIUM (5.0/10) | Ensure Bedrock Agent is encrypted with a CMK |
| [CKV_AWS_374](./rules/CKV_AWS_374.md) | LOW (2.0/10) | Ensure AWS CloudFront web distribution has geo restriction enabled |
| [CKV_AWS_375](./rules/CKV_AWS_375.md) | LOW (2.0/10) | Ensure AWS S3 bucket does not have global view ACL permissions enabled |
| [CKV_AWS_376](./rules/CKV_AWS_376.md) | HIGH (7.5/10) | Ensure AWS Elastic Load Balancer listener uses TLS/SSL |
| [CKV_AWS_377](./rules/CKV_AWS_377.md) | LOW (2.0/10) | Ensure Route 53 domains have transfer lock protection |
| [CKV_AWS_378](./rules/CKV_AWS_378.md) | HIGH (7.5/10) | Ensure AWS Load Balancer doesn't use HTTP protocol |
| [CKV_AWS_379](./rules/CKV_AWS_379.md) | HIGH (7.5/10) | Ensure AWS S3 bucket is configured with secure data transport policy |
| [CKV_AWS_380](./rules/CKV_AWS_380.md) | MEDIUM (5/10) | Ensure AWS Transfer Server uses latest Security Policy |
| [CKV_AWS_381](./rules/CKV_AWS_381.md) | LOW (2.0/10) | Make sure that aws_codegurureviewer_repository_association has a CMK |
| [CKV_AWS_382](./rules/CKV_AWS_382.md) | LOW (2.0/10) | Ensure no security groups allow egress from 0.0.0.0:0 to port -1 |
| [CKV_AWS_383](./rules/CKV_AWS_383.md) | LOW (2.0/10) | Ensure AWS Bedrock agent is associated with Bedrock guardrails |
| [CKV_AWS_384](./rules/CKV_AWS_384.md) | MEDIUM (5.0/10) | Ensure no hard-coded secrets exist in Parameter Store values |
| [CKV_AWS_385](./rules/CKV_AWS_385.md) | HIGH (7/10) | Ensure AWS SNS topic policies do not allow cross-account access |
| [CKV_AWS_386](./rules/CKV_AWS_386.md) | LOW (2.0/10) | Reduce potential for WhoAMI cloud image name confusion attack |
| [CKV_AWS_387](./rules/CKV_AWS_387.md) | LOW (2.0/10) | Ensure SQS policy does not allow public access through wildcards |
| [CKV_AWS_388](./rules/CKV_AWS_388.md) | HIGH (7.5/10) | Ensure AWS Aurora PostgreSQL is not exposed to local file read vulnerability |
| [CKV_AWS_389](./rules/CKV_AWS_389.md) | MEDIUM (5.5/10) | Ensure AWS Auto Scaling group launch configuration doesn't have public IP address assignment enabled |
| [CKV_AWS_390](./rules/CKV_AWS_390.md) | HIGH (7.5/10) | Ensure AWS EMR block public access setting is enabled |
| [CKV_AWS_391](./rules/CKV_AWS_391.md) | CRITICAL (9/10) | Avoid AWS Redshift cluster with commonly used master username and public access setting enabled |
| [CKV_AWS_392](./rules/CKV_AWS_392.md) | HIGH (7.8/10) | Ensure AWS S3 access point block public access setting is enabled |
| [CKV_AWS_393](./rules/CKV_AWS_393.md) | HIGH (7.5/10) | Ensure AWS GitHub Actions OIDC authorization policies only allow safe claims and claim order on IAM role |

## AZURE

| Rule ID | Severity | Description |
|---|---|---|
| [CKV2_AZURE_1](./rules/CKV2_AZURE_1.md) | HIGH (7.5/10) | Ensure storage for critical data are encrypted with Customer Managed Key |
| [CKV_AZURE_1](./rules/CKV_AZURE_1.md) | HIGH (7.5/10) | Ensure Azure Instance does not use basic authentication (Use SSH Key Instead) |
| [CKV2_AZURE_2](./rules/CKV2_AZURE_2.md) | LOW (2.0/10) | Ensure that Vulnerability Assessment (VA) is enabled on a SQL server by setting a Storage Account |
| [CKV_AZURE_2](./rules/CKV_AZURE_2.md) | LOW (2.0/10) | Ensure Azure managed disk have encryption enabled |
| [CKV2_AZURE_3](./rules/CKV2_AZURE_3.md) | LOW (2.0/10) | Ensure that VA setting Periodic Recurring Scans is enabled on a SQL server |
| [CKV_AZURE_3](./rules/CKV_AZURE_3.md) | LOW (2.0/10) | Ensure that 'supportsHttpsTrafficOnly' is set to 'true' |
| [CKV2_AZURE_4](./rules/CKV2_AZURE_4.md) | LOW (2.0/10) | Ensure Azure SQL server ADS VA Send scan reports to is configured |
| [CKV_AZURE_4](./rules/CKV_AZURE_4.md) | LOW (2.0/10) | Ensure AKS logging to Azure Monitoring is Configured |
| [CKV2_AZURE_5](./rules/CKV2_AZURE_5.md) | LOW (2.0/10) | Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server |
| [CKV_AZURE_5](./rules/CKV_AZURE_5.md) | MEDIUM (5.0/10) | Ensure RBAC is enabled on AKS clusters |
| [CKV2_AZURE_6](./rules/CKV2_AZURE_6.md) | HIGH (7.5/10) | Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled |
| [CKV_AZURE_6](./rules/CKV_AZURE_6.md) | LOW (2.0/10) | Ensure AKS has an API Server Authorized IP Ranges enabled |
| [CKV2_AZURE_7](./rules/CKV2_AZURE_7.md) | LOW (2.0/10) | Ensure that Azure Active Directory Admin is configured |
| [CKV_AZURE_7](./rules/CKV_AZURE_7.md) | LOW (2.0/10) | Ensure AKS cluster has Network Policy configured |
| [CKV2_AZURE_8](./rules/CKV2_AZURE_8.md) | CRITICAL (9/10) | Ensure the storage container storing the activity logs is not publicly accessible |
| [CKV_AZURE_8](./rules/CKV_AZURE_8.md) | HIGH (8/10) | Ensure Kubernetes Dashboard is disabled |
| [CKV2_AZURE_9](./rules/CKV2_AZURE_9.md) | LOW (2.0/10) | Ensure Virtual Machines are utilizing Managed Disks |
| [CKV_AZURE_9](./rules/CKV_AZURE_9.md) | HIGH (7.5/10) | Ensure that RDP access is restricted from the internet |
| [CKV2_AZURE_10](./rules/CKV2_AZURE_10.md) | LOW (2.0/10) | Ensure that Microsoft Antimalware is configured to automatically updates for Virtual Machines |
| [CKV_AZURE_10](./rules/CKV_AZURE_10.md) | CRITICAL (9/10) | Ensure that SSH access is restricted from the internet |
| [CKV2_AZURE_11](./rules/CKV2_AZURE_11.md) | LOW (2.0/10) | Ensure that Azure Data Explorer encryption at rest uses a customer-managed key |
| [CKV_AZURE_11](./rules/CKV_AZURE_11.md) | CRITICAL (9/10) | Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) |
| [CKV2_AZURE_12](./rules/CKV2_AZURE_12.md) | LOW (2.0/10) | Ensure that virtual machines are backed up using Azure Backup |
| [CKV_AZURE_12](./rules/CKV_AZURE_12.md) | LOW (2.0/10) | Ensure that Network Security Group Flow Log retention period is 'greater than 90 days' |
| [CKV2_AZURE_13](./rules/CKV2_AZURE_13.md) | LOW (2.0/10) | Ensure that sql servers enables data security policy |
| [CKV_AZURE_13](./rules/CKV_AZURE_13.md) | LOW (2.0/10) | Ensure App Service Authentication is set on Azure App Service |
| [CKV2_AZURE_14](./rules/CKV2_AZURE_14.md) | LOW (2.0/10) | Ensure that Unattached disks are encrypted |
| [CKV_AZURE_14](./rules/CKV_AZURE_14.md) | HIGH (7/10) | Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service |
| [CKV2_AZURE_15](./rules/CKV2_AZURE_15.md) | LOW (2.0/10) | Ensure that Azure data factories are encrypted with a customer-managed key |
| [CKV_AZURE_15](./rules/CKV_AZURE_15.md) | MEDIUM (5.5/10) | Ensure web app is using the latest version of TLS encryption |
| [CKV2_AZURE_16](./rules/CKV2_AZURE_16.md) | LOW (2.0/10) | Ensure that MySQL server enables customer-managed key for encryption |
| [CKV_AZURE_16](./rules/CKV_AZURE_16.md) | MEDIUM (5.0/10) | Ensure that Register with Azure Active Directory is enabled on App Service |
| [CKV2_AZURE_17](./rules/CKV2_AZURE_17.md) | LOW (2.0/10) | Ensure that PostgreSQL server enables customer-managed key for encryption |
| [CKV_AZURE_17](./rules/CKV_AZURE_17.md) | MEDIUM (5.5/10) | Ensure the web app has 'Client Certificates (Incoming client certificates)' set |
| [CKV_AZURE_18](./rules/CKV_AZURE_18.md) | LOW (2.5/10) | Ensure that 'HTTP Version' is the latest if used to run the web app |
| [CKV2_AZURE_19](./rules/CKV2_AZURE_19.md) | LOW (2.0/10) | Ensure that Azure Synapse workspaces have no IP firewall rules attached |
| [CKV_AZURE_19](./rules/CKV_AZURE_19.md) | LOW (2.0/10) | Ensure that standard pricing tier is selected |
| [CKV2_AZURE_20](./rules/CKV2_AZURE_20.md) | LOW (2.0/10) | Ensure Storage logging is enabled for Table service for read requests |
| [CKV_AZURE_20](./rules/CKV_AZURE_20.md) | LOW (2.0/10) | Ensure that security contact 'Phone number' is set |
| [CKV2_AZURE_21](./rules/CKV2_AZURE_21.md) | LOW (2.0/10) | Ensure Storage logging is enabled for Blob service for read requests |
| [CKV_AZURE_21](./rules/CKV_AZURE_21.md) | LOW (2.0/10) | Ensure that 'Send email notification for high severity alerts' is set to 'On' |
| [CKV2_AZURE_22](./rules/CKV2_AZURE_22.md) | LOW (2.0/10) | Ensure that Cognitive Services enables customer-managed key for encryption |
| [CKV_AZURE_22](./rules/CKV_AZURE_22.md) | LOW (2.0/10) | Ensure that 'Send email notification for high severity alerts' is set to 'On' |
| [CKV2_AZURE_23](./rules/CKV2_AZURE_23.md) | MEDIUM (5/10) | Ensure Azure spring cloud is configured with Virtual network (Vnet) |
| [CKV_AZURE_23](./rules/CKV_AZURE_23.md) | LOW (2.0/10) | Ensure that 'Auditing' is set to 'Enabled' for SQL servers |
| [CKV2_AZURE_24](./rules/CKV2_AZURE_24.md) | MEDIUM (5.0/10) | Ensure Azure automation account does NOT have overly permissive network access |
| [CKV_AZURE_24](./rules/CKV_AZURE_24.md) | HIGH (7.5/10) | Ensure that 'Auditing' Retention is 'greater than 90 days' for SQL servers |
| [CKV2_AZURE_25](./rules/CKV2_AZURE_25.md) | LOW (2.0/10) | Ensure Azure SQL database Transparent Data Encryption (TDE) is enabled |
| [CKV_AZURE_25](./rules/CKV_AZURE_25.md) | HIGH (7.5/10) | Azure SQL Server threat detection alerts are enabled for all threat types |
| [CKV2_AZURE_26](./rules/CKV2_AZURE_26.md) | CRITICAL (9/10) | Ensure Azure PostgreSQL Flexible server is not configured with overly permissive network access |
| [CKV_AZURE_26](./rules/CKV_AZURE_26.md) | HIGH (7.5/10) | Ensure that 'Send Alerts To' is enabled for MSSQL servers |
| [CKV2_AZURE_27](./rules/CKV2_AZURE_27.md) | LOW (2.0/10) | Ensure Azure AD authentication is enabled for Azure SQL (MSSQL) |
| [CKV_AZURE_27](./rules/CKV_AZURE_27.md) | LOW (2.0/10) | Ensure that 'Email service and co-administrators' is 'Enabled' for MSSQL servers |
| [CKV2_AZURE_28](./rules/CKV2_AZURE_28.md) | MEDIUM (5/10) | Ensure Container Instance is configured with managed identity |
| [CKV_AZURE_28](./rules/CKV_AZURE_28.md) | HIGH (7.5/10) | Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server |
| [CKV2_AZURE_29](./rules/CKV2_AZURE_29.md) | MEDIUM (5/10) | Ensure AKS cluster has Azure CNI networking enabled |
| [CKV_AZURE_29](./rules/CKV_AZURE_29.md) | HIGH (7.5/10) | Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server |
| [CKV2_AZURE_30](./rules/CKV2_AZURE_30.md) | LOW (2.0/10) | Ensure Azure Container Registry (ACR) has HTTPS enabled for webhook |
| [CKV_AZURE_30](./rules/CKV_AZURE_30.md) | LOW (2.0/10) | Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server |
| [CKV2_AZURE_31](./rules/CKV2_AZURE_31.md) | HIGH (7.5/10) | Ensure VNET subnet is configured with a Network Security Group (NSG) |
| [CKV_AZURE_31](./rules/CKV_AZURE_31.md) | LOW (2.0/10) | Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server |
| [CKV2_AZURE_32](./rules/CKV2_AZURE_32.md) | MEDIUM (6/10) | Ensure private endpoint is configured to key vault |
| [CKV_AZURE_32](./rules/CKV_AZURE_32.md) | LOW (2.0/10) | Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server |
| [CKV2_AZURE_33](./rules/CKV2_AZURE_33.md) | MEDIUM (6/10) | Ensure storage account is configured with private endpoint |
| [CKV_AZURE_33](./rules/CKV_AZURE_33.md) | LOW (2.0/10) | Ensure Storage logging is enabled for Queue service for read, write and delete requests |
| [CKV2_AZURE_34](./rules/CKV2_AZURE_34.md) | HIGH (7.5/10) | Ensure Azure SQL server firewall is not overly permissive |
| [CKV_AZURE_34](./rules/CKV_AZURE_34.md) | CRITICAL (9.3/10) | Ensure that 'Public access level' is set to Private for blob containers |
| [CKV2_AZURE_35](./rules/CKV2_AZURE_35.md) | LOW (2.0/10) | Ensure Azure recovery services vault is configured with managed identity |
| [CKV_AZURE_35](./rules/CKV_AZURE_35.md) | HIGH (7.5/10) | Ensure default network access rule for Storage Accounts is set to deny |
| [CKV2_AZURE_36](./rules/CKV2_AZURE_36.md) | LOW (2.0/10) | Ensure Azure automation account is configured with managed identity |
| [CKV_AZURE_36](./rules/CKV_AZURE_36.md) | LOW (2.0/10) | Ensure 'Trusted Microsoft Services' is enabled for Storage Account access |
| [CKV2_AZURE_37](./rules/CKV2_AZURE_37.md) | LOW (2.0/10) | Ensure Azure MariaDB server is using latest TLS (1.2) |
| [CKV_AZURE_37](./rules/CKV_AZURE_37.md) | LOW (2.0/10) | Ensure that Activity Log Retention is set 365 days or greater |
| [CKV2_AZURE_38](./rules/CKV2_AZURE_38.md) | LOW (2.0/10) | Ensure soft-delete is enabled on Azure storage account |
| [CKV_AZURE_38](./rules/CKV_AZURE_38.md) | LOW (2.0/10) | Ensure audit profile captures all the activities |
| [CKV2_AZURE_39](./rules/CKV2_AZURE_39.md) | HIGH (7.5/10) | Ensure Azure VM is not configured with public IP and serial console access |
| [CKV_AZURE_39](./rules/CKV_AZURE_39.md) | HIGH (7.5/10) | Ensure that no custom subscription owner roles are created |
| [CKV2_AZURE_40](./rules/CKV2_AZURE_40.md) | LOW (2.0/10) | Ensure storage account is not configured with Shared Key authorization |
| [CKV_AZURE_40](./rules/CKV_AZURE_40.md) | HIGH (7.5/10) | Ensure that the expiration date is set on all keys |
| [CKV2_AZURE_41](./rules/CKV2_AZURE_41.md) | LOW (2.0/10) | Ensure storage account is configured with SAS expiration policy |
| [CKV_AZURE_41](./rules/CKV_AZURE_41.md) | HIGH (7.5/10) | Ensure that the expiration date is set on all secrets |
| [CKV2_AZURE_42](./rules/CKV2_AZURE_42.md) | HIGH (7/10) | Ensure Azure PostgreSQL server is configured with private endpoint |
| [CKV_AZURE_42](./rules/CKV_AZURE_42.md) | LOW (2.0/10) | Ensure the key vault is recoverable |
| [CKV2_AZURE_43](./rules/CKV2_AZURE_43.md) | HIGH (7/10) | Ensure Azure MariaDB server is configured with private endpoint |
| [CKV_AZURE_43](./rules/CKV_AZURE_43.md) | LOW (2.0/10) | Ensure Storage Accounts adhere to the naming rules |
| [CKV2_AZURE_44](./rules/CKV2_AZURE_44.md) | HIGH (7/10) | Ensure Azure MySQL server is configured with private endpoint |
| [CKV_AZURE_44](./rules/CKV_AZURE_44.md) | LOW (2.0/10) | Ensure Storage Account is using the latest version of TLS encryption |
| [CKV2_AZURE_45](./rules/CKV2_AZURE_45.md) | HIGH (7/10) | Ensure Microsoft SQL server is configured with private endpoint |
| [CKV_AZURE_45](./rules/CKV_AZURE_45.md) | HIGH (7.5/10) | Ensure that no sensitive credentials are exposed in VM custom_data |
| [CKV2_AZURE_46](./rules/CKV2_AZURE_46.md) | MEDIUM (5.0/10) | Ensure that Azure Synapse Workspace vulnerability assessment is enabled |
| [CKV2_AZURE_47](./rules/CKV2_AZURE_47.md) | MEDIUM (5.0/10) | Ensure storage account is configured without blob anonymous access |
| [CKV_AZURE_47](./rules/CKV_AZURE_47.md) | HIGH (7.5/10) | Ensure 'Enforce SSL connection' is set to 'ENABLED' for MariaDB servers |
| [CKV2_AZURE_48](./rules/CKV2_AZURE_48.md) | LOW (2.0/10) | Ensure that Databricks Workspaces enables customer-managed key for root DBFS encryption |
| [CKV_AZURE_48](./rules/CKV_AZURE_48.md) | HIGH (8/10) | Ensure 'public network access enabled' is set to 'False' for MariaDB servers |
| [CKV2_AZURE_49](./rules/CKV2_AZURE_49.md) | HIGH (7.5/10) | Ensure that Azure Machine learning workspace is not configured with overly permissive network access |
| [CKV_AZURE_49](./rules/CKV_AZURE_49.md) | HIGH (7.5/10) | Ensure Azure linux scale set does not use basic authentication(Use SSH Key Instead) |
| [CKV2_AZURE_50](./rules/CKV2_AZURE_50.md) | HIGH (7.5/10) | Ensure Azure Storage Account storing Machine Learning workspace high business impact data is not publicly accessible |
| [CKV_AZURE_50](./rules/CKV_AZURE_50.md) | MEDIUM (5.0/10) | Ensure Virtual Machine Extensions are not Installed |
| [CKV2_AZURE_51](./rules/CKV2_AZURE_51.md) | LOW (2.0/10) | Ensure Synapse SQL Pool has a security alert policy |
| [CKV2_AZURE_52](./rules/CKV2_AZURE_52.md) | LOW (2.0/10) | Ensure Synapse SQL Pool has vulnerability assessment attached |
| [CKV_AZURE_52](./rules/CKV_AZURE_52.md) | MEDIUM (5.0/10) | Ensure MSSQL is using the latest version of TLS encryption |
| [CKV2_AZURE_53](./rules/CKV2_AZURE_53.md) | LOW (2.0/10) | Ensure Azure Synapse Workspace has extended audit logs |
| [CKV_AZURE_53](./rules/CKV_AZURE_53.md) | HIGH (7.5/10) | Ensure 'public network access enabled' is set to 'False' for mySQL servers |
| [CKV2_AZURE_54](./rules/CKV2_AZURE_54.md) | LOW (2.0/10) | Ensure log monitoring is enabled for Synapse SQL Pool |
| [CKV_AZURE_54](./rules/CKV_AZURE_54.md) | HIGH (7/10) | Ensure MySQL is using the latest version of TLS encryption |
| [CKV2_AZURE_55](./rules/CKV2_AZURE_55.md) | HIGH (7.5/10) | Ensure Azure Spring Cloud app end-to-end TLS is enabled |
| [CKV_AZURE_55](./rules/CKV_AZURE_55.md) | LOW (2.0/10) | Ensure that Azure Defender is set to On for Servers |
| [CKV2_AZURE_56](./rules/CKV2_AZURE_56.md) | MEDIUM (5.0/10) | Ensure Azure MySQL Flexible Server is configured with private endpoint |
| [CKV_AZURE_56](./rules/CKV_AZURE_56.md) | LOW (2.0/10) | Ensure that function apps enables Authentication |
| [CKV2_AZURE_57](./rules/CKV2_AZURE_57.md) | MEDIUM (5.0/10) | Ensure PostgreSQL Flexible Server is configured with private endpoint |
| [CKV_AZURE_57](./rules/CKV_AZURE_57.md) | MEDIUM (6/10) | Ensure that CORS disallows every resource to access app services |
| [CKV_AZURE_58](./rules/CKV_AZURE_58.md) | LOW (2.0/10) | Ensure that Azure Synapse workspaces enables managed virtual networks |
| [CKV_AZURE_59](./rules/CKV_AZURE_59.md) | HIGH (7.5/10) | Ensure that Storage accounts disallow public access |
| [CKV_AZURE_61](./rules/CKV_AZURE_61.md) | LOW (2.0/10) | Ensure that Azure Defender is set to On for App Service |
| [CKV_AZURE_62](./rules/CKV_AZURE_62.md) | LOW (2.0/10) | Ensure that function apps are not accessible from all regions |
| [CKV_AZURE_63](./rules/CKV_AZURE_63.md) | LOW (2.0/10) | Ensure that App service enables HTTP logging |
| [CKV_AZURE_64](./rules/CKV_AZURE_64.md) | HIGH (7/10) | Ensure that Azure File Sync disables public network access |
| [CKV_AZURE_65](./rules/CKV_AZURE_65.md) | LOW (2.0/10) | Ensure that App service enables detailed error messages |
| [CKV_AZURE_66](./rules/CKV_AZURE_66.md) | LOW (2.0/10) | Ensure that App service enables failed request tracing |
| [CKV_AZURE_67](./rules/CKV_AZURE_67.md) | LOW (2.0/10) | Ensure that 'HTTP Version' is the latest, if used to run the Function app |
| [CKV_AZURE_68](./rules/CKV_AZURE_68.md) | HIGH (7.5/10) | Ensure that PostgreSQL server disables public network access |
| [CKV_AZURE_69](./rules/CKV_AZURE_69.md) | LOW (2.0/10) | Ensure that Azure Defender is set to On for Azure SQL database servers |
| [CKV_AZURE_70](./rules/CKV_AZURE_70.md) | HIGH (7.5/10) | Ensure that Function apps is only accessible over HTTPS |
| [CKV_AZURE_71](./rules/CKV_AZURE_71.md) | LOW (2.0/10) | Ensure that Managed identity provider is enabled for app services |
| [CKV_AZURE_72](./rules/CKV_AZURE_72.md) | MEDIUM (5.0/10) | Ensure that remote debugging is not enabled for app services |
| [CKV_AZURE_73](./rules/CKV_AZURE_73.md) | LOW (2.0/10) | Ensure that Automation account variables are encrypted |
| [CKV_AZURE_74](./rules/CKV_AZURE_74.md) | LOW (2.0/10) | Ensure that Azure Data Explorer (Kusto) uses disk encryption |
| [CKV_AZURE_75](./rules/CKV_AZURE_75.md) | LOW (2.0/10) | Ensure that Azure Data Explorer uses double encryption |
| [CKV_AZURE_76](./rules/CKV_AZURE_76.md) | LOW (2.0/10) | Ensure that Azure Batch account uses key vault to encrypt data |
| [CKV_AZURE_77](./rules/CKV_AZURE_77.md) | CRITICAL (9/10) | Ensure that UDP Services are restricted from the Internet |
| [CKV_AZURE_78](./rules/CKV_AZURE_78.md) | HIGH (7.5/10) | Ensure FTP deployments are disabled |
| [CKV_AZURE_79](./rules/CKV_AZURE_79.md) | LOW (2.0/10) | Ensure that Azure Defender is set to On for SQL servers on machines |
| [CKV_AZURE_80](./rules/CKV_AZURE_80.md) | LOW (2.0/10) | Ensure that 'Net Framework' version is the latest, if used as a part of the web app |
| [CKV_AZURE_81](./rules/CKV_AZURE_81.md) | LOW (2.0/10) | Ensure that 'PHP version' is the latest, if used to run the web app |
| [CKV_AZURE_82](./rules/CKV_AZURE_82.md) | LOW (2.0/10) | Ensure that 'Python version' is the latest, if used to run the web app |
| [CKV_AZURE_83](./rules/CKV_AZURE_83.md) | LOW (2.0/10) | Ensure that 'Java version' is the latest, if used to run the web app |
| [CKV_AZURE_84](./rules/CKV_AZURE_84.md) | LOW (2.0/10) | Ensure that Azure Defender is set to On for Storage |
| [CKV_AZURE_85](./rules/CKV_AZURE_85.md) | HIGH (7.5/10) | Ensure that Azure Defender is set to On for Kubernetes |
| [CKV_AZURE_86](./rules/CKV_AZURE_86.md) | HIGH (7.5/10) | Ensure that Azure Defender is set to On for Container Registries |
| [CKV_AZURE_87](./rules/CKV_AZURE_87.md) | LOW (2.0/10) | Ensure that Azure Defender is set to On for Key Vault |
| [CKV_AZURE_88](./rules/CKV_AZURE_88.md) | LOW (2.0/10) | Ensure that app services use Azure Files |
| [CKV_AZURE_89](./rules/CKV_AZURE_89.md) | HIGH (7.5/10) | Ensure that Azure Cache for Redis disables public network access |
| [CKV_AZURE_91](./rules/CKV_AZURE_91.md) | LOW (2.0/10) | Ensure that only SSL are enabled for Cache for Redis |
| [CKV_AZURE_92](./rules/CKV_AZURE_92.md) | LOW (2.0/10) | Ensure that Virtual Machines use managed disks |
| [CKV_AZURE_93](./rules/CKV_AZURE_93.md) | LOW (2.0/10) | Ensure that managed disks use a specific set of disk encryption sets for the customer-managed key encryption |
| [CKV_AZURE_94](./rules/CKV_AZURE_94.md) | LOW (2.0/10) | Ensure that My SQL server enables geo-redundant backups |
| [CKV_AZURE_95](./rules/CKV_AZURE_95.md) | LOW (2.0/10) | Ensure that automatic OS image patching is enabled for Virtual Machine Scale Sets |
| [CKV_AZURE_96](./rules/CKV_AZURE_96.md) | LOW (2.0/10) | Ensure that MySQL server enables infrastructure encryption |
| [CKV_AZURE_97](./rules/CKV_AZURE_97.md) | LOW (2.0/10) | Ensure that Virtual machine scale sets have encryption at host enabled |
| [CKV_AZURE_98](./rules/CKV_AZURE_98.md) | LOW (2.0/10) | Ensure that Azure Container group is deployed into virtual network |
| [CKV_AZURE_99](./rules/CKV_AZURE_99.md) | HIGH (7.5/10) | Ensure Cosmos DB accounts have restricted access |
| [CKV_AZURE_100](./rules/CKV_AZURE_100.md) | LOW (2.0/10) | Ensure that Cosmos DB accounts have customer-managed keys to encrypt data at rest |
| [CKV_AZURE_101](./rules/CKV_AZURE_101.md) | HIGH (7.5/10) | Ensure that Azure Cosmos DB disables public network access |
| [CKV_AZURE_102](./rules/CKV_AZURE_102.md) | LOW (2.0/10) | Ensure that PostgreSQL server enables geo-redundant backups |
| [CKV_AZURE_103](./rules/CKV_AZURE_103.md) | LOW (2.0/10) | Ensure that Azure Data Factory uses Git repository for source control |
| [CKV_AZURE_104](./rules/CKV_AZURE_104.md) | HIGH (7/10) | Ensure that Azure Data factory public network access is disabled |
| [CKV_AZURE_105](./rules/CKV_AZURE_105.md) | MEDIUM (5.0/10) | Ensure that Data Lake Store accounts enables encryption |
| [CKV_AZURE_106](./rules/CKV_AZURE_106.md) | HIGH (7/10) | Ensure that Azure Event Grid Domain public network access is disabled |
| [CKV_AZURE_107](./rules/CKV_AZURE_107.md) | LOW (2.0/10) | Ensure that API management services use virtual networks |
| [CKV_AZURE_108](./rules/CKV_AZURE_108.md) | HIGH (7/10) | Ensure that Azure IoT Hub disables public network access |
| [CKV_AZURE_109](./rules/CKV_AZURE_109.md) | MEDIUM (5.0/10) | Ensure that key vault allows firewall rules settings |
| [CKV_AZURE_110](./rules/CKV_AZURE_110.md) | LOW (2.0/10) | Ensure that key vault enables purge protection |
| [CKV_AZURE_111](./rules/CKV_AZURE_111.md) | LOW (2.0/10) | Ensure that key vault enables soft delete |
| [CKV_AZURE_112](./rules/CKV_AZURE_112.md) | LOW (2.0/10) | Ensure that key vault key is backed by HSM |
| [CKV_AZURE_113](./rules/CKV_AZURE_113.md) | HIGH (7.5/10) | Ensure that SQL server disables public network access |
| [CKV_AZURE_114](./rules/CKV_AZURE_114.md) | LOW (2.0/10) | Ensure that key vault secrets have "content_type" set |
| [CKV_AZURE_115](./rules/CKV_AZURE_115.md) | LOW (2.0/10) | Ensure that AKS enables private clusters |
| [CKV_AZURE_116](./rules/CKV_AZURE_116.md) | LOW (2.0/10) | Ensure that AKS uses Azure Policies Add-on |
| [CKV_AZURE_117](./rules/CKV_AZURE_117.md) | LOW (2.0/10) | Ensure that AKS uses disk encryption set |
| [CKV_AZURE_118](./rules/CKV_AZURE_118.md) | HIGH (7.5/10) | Ensure that Network Interfaces disable IP forwarding |
| [CKV_AZURE_119](./rules/CKV_AZURE_119.md) | HIGH (8/10) | Ensure that Network Interfaces don't use public IPs |
| [CKV_AZURE_120](./rules/CKV_AZURE_120.md) | LOW (2.0/10) | Ensure that Application Gateway enables WAF |
| [CKV_AZURE_121](./rules/CKV_AZURE_121.md) | LOW (2.0/10) | Ensure that Azure Front Door enables WAF |
| [CKV_AZURE_122](./rules/CKV_AZURE_122.md) | LOW (2.0/10) | Ensure that Application Gateway uses WAF in "Detection" or "Prevention" modes |
| [CKV_AZURE_123](./rules/CKV_AZURE_123.md) | LOW (2.0/10) | Ensure that Azure Front Door uses WAF in "Detection" or "Prevention" modes |
| [CKV_AZURE_124](./rules/CKV_AZURE_124.md) | HIGH (7.5/10) | Ensure that Azure Cognitive Search disables public network access |
| [CKV_AZURE_125](./rules/CKV_AZURE_125.md) | LOW (2.0/10) | Ensures that Service Fabric use three levels of protection available |
| [CKV_AZURE_126](./rules/CKV_AZURE_126.md) | LOW (2.0/10) | Ensures that Active Directory is used for authentication for Service Fabric |
| [CKV_AZURE_127](./rules/CKV_AZURE_127.md) | LOW (2.0/10) | Ensure that My SQL server enables Threat detection policy |
| [CKV_AZURE_128](./rules/CKV_AZURE_128.md) | LOW (2.0/10) | Ensure that PostgreSQL server enables Threat detection policy |
| [CKV_AZURE_129](./rules/CKV_AZURE_129.md) | LOW (2.0/10) | Ensure that MariaDB server enables geo-redundant backups |
| [CKV_AZURE_130](./rules/CKV_AZURE_130.md) | LOW (2.0/10) | Ensure that PostgreSQL server enables infrastructure encryption |
| [CKV_AZURE_131](./rules/CKV_AZURE_131.md) | LOW (2.0/10) | SecureString parameter should not have hardcoded default values / Ensure that 'Security contact emails' is set |
| [CKV_AZURE_132](./rules/CKV_AZURE_132.md) | LOW (2.0/10) | Ensure cosmosdb does not allow privileged escalation by restricting management plane changes |
| [CKV_AZURE_133](./rules/CKV_AZURE_133.md) | LOW (2.0/10) | Ensure Front Door WAF prevents message lookup in Log4j2 (CVE-2021-44228, Log4Shell) |
| [CKV_AZURE_134](./rules/CKV_AZURE_134.md) | HIGH (7.5/10) | Ensure that Cognitive Services accounts disable public network access |
| [CKV_AZURE_135](./rules/CKV_AZURE_135.md) | LOW (2.0/10) | Ensure Application Gateway WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell |
| [CKV_AZURE_136](./rules/CKV_AZURE_136.md) | LOW (2.0/10) | Ensure that PostgreSQL Flexible server enables geo-redundant backups |
| [CKV_AZURE_137](./rules/CKV_AZURE_137.md) | LOW (2.0/10) | Ensure ACR admin account is disabled |
| [CKV_AZURE_138](./rules/CKV_AZURE_138.md) | LOW (2.0/10) | Ensures that ACR disables anonymous pulling of images |
| [CKV_AZURE_139](./rules/CKV_AZURE_139.md) | HIGH (7.5/10) | Ensure ACR set to disable public networking |
| [CKV_AZURE_140](./rules/CKV_AZURE_140.md) | LOW (2.0/10) | Ensure that Local Authentication is disabled on CosmosDB |
| [CKV_AZURE_141](./rules/CKV_AZURE_141.md) | LOW (2.0/10) | Ensure AKS local admin account is disabled |
| [CKV_AZURE_142](./rules/CKV_AZURE_142.md) | LOW (2.0/10) | Ensure Machine Learning Compute Cluster Local Authentication is disabled |
| [CKV_AZURE_143](./rules/CKV_AZURE_143.md) | HIGH (8/10) | Ensure AKS cluster nodes do not have public IP addresses |
| [CKV_AZURE_144](./rules/CKV_AZURE_144.md) | LOW (2.0/10) | Ensure that Public Access is disabled for Machine Learning Workspace |
| [CKV_AZURE_145](./rules/CKV_AZURE_145.md) | HIGH (7/10) | Ensure Function app is using the latest version of TLS encryption |
| [CKV_AZURE_146](./rules/CKV_AZURE_146.md) | LOW (2.0/10) | Ensure server parameter 'log_retention' is set to 'ON' for PostgreSQL Database Server |
| [CKV_AZURE_147](./rules/CKV_AZURE_147.md) | LOW (2.0/10) | Ensure PostgreSQL is using the latest version of TLS encryption |
| [CKV_AZURE_148](./rules/CKV_AZURE_148.md) | MEDIUM (5.5/10) | Ensure Redis Cache is using the latest version of TLS encryption |
| [CKV_AZURE_149](./rules/CKV_AZURE_149.md) | LOW (2.0/10) | Ensure that Virtual machine does not enable password authentication |
| [CKV_AZURE_150](./rules/CKV_AZURE_150.md) | LOW (2.0/10) | Ensure Machine Learning Compute Cluster Minimum Nodes Set To 0 |
| [CKV_AZURE_151](./rules/CKV_AZURE_151.md) | LOW (2.0/10) | Ensure Windows VM enables encryption |
| [CKV_AZURE_152](./rules/CKV_AZURE_152.md) | HIGH (7/10) | Ensure Client Certificates are enforced for API management |
| [CKV_AZURE_153](./rules/CKV_AZURE_153.md) | HIGH (7/10) | Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service Slot |
| [CKV_AZURE_154](./rules/CKV_AZURE_154.md) | MEDIUM (5.5/10) | Ensure the App service slot is using the latest version of TLS encryption |
| [CKV_AZURE_155](./rules/CKV_AZURE_155.md) | HIGH (7.5/10) | Ensure debugging is disabled for the App service slot |
| [CKV_AZURE_156](./rules/CKV_AZURE_156.md) | LOW (2.0/10) | Ensure default Auditing policy for a SQL Server is configured to capture and retain the activity logs |
| [CKV_AZURE_157](./rules/CKV_AZURE_157.md) | LOW (2.0/10) | Ensure that Synapse workspace has data_exfiltration_protection_enabled |
| [CKV_AZURE_158](./rules/CKV_AZURE_158.md) | LOW (2.0/10) | Ensure Databricks Workspace data plane to control plane communication happens over private link |
| [CKV_AZURE_159](./rules/CKV_AZURE_159.md) | LOW (2.0/10) | Ensure function app builtin logging is enabled |
| [CKV_AZURE_160](./rules/CKV_AZURE_160.md) | HIGH (7/10) | Ensure that HTTP (port 80) access is restricted from the internet |
| [CKV_AZURE_161](./rules/CKV_AZURE_161.md) | HIGH (7/10) | Ensures Spring Cloud API Portal is enabled on for HTTPS |
| [CKV_AZURE_162](./rules/CKV_AZURE_162.md) | HIGH (7.5/10) | Ensures Spring Cloud API Portal Public Access Is Disabled |
| [CKV_AZURE_163](./rules/CKV_AZURE_163.md) | MEDIUM (5.0/10) | Enable vulnerability scanning for container images |
| [CKV_AZURE_164](./rules/CKV_AZURE_164.md) | MEDIUM (5.0/10) | Ensures that ACR uses signed/trusted images |
| [CKV_AZURE_165](./rules/CKV_AZURE_165.md) | MEDIUM (5.0/10) | Ensure geo-replicated container registries to match multi-region container deployments. |
| [CKV_AZURE_166](./rules/CKV_AZURE_166.md) | MEDIUM (5.0/10) | Ensure container image quarantine, scan, and mark images verified |
| [CKV_AZURE_167](./rules/CKV_AZURE_167.md) | LOW (2.0/10) | Ensure a retention policy is set to cleanup untagged manifests. |
| [CKV_AZURE_168](./rules/CKV_AZURE_168.md) | LOW (2.0/10) | Ensure Azure Kubernetes Cluster (AKS) nodes should use a minimum number of 50 pods. |
| [CKV_AZURE_169](./rules/CKV_AZURE_169.md) | LOW (2.0/10) | Ensure Azure Kubernetes Cluster (AKS) nodes use scale sets |
| [CKV_AZURE_170](./rules/CKV_AZURE_170.md) | LOW (2.0/10) | Ensure that AKS use the Paid Sku for its SLA |
| [CKV_AZURE_171](./rules/CKV_AZURE_171.md) | LOW (2.0/10) | Ensure AKS cluster upgrade channel is chosen |
| [CKV_AZURE_172](./rules/CKV_AZURE_172.md) | MEDIUM (5.0/10) | Ensure autorotation of Secrets Store CSI Driver secrets for AKS clusters |
| [CKV_AZURE_173](./rules/CKV_AZURE_173.md) | HIGH (7.5/10) | Ensure API management uses at least TLS 1.2 |
| [CKV_AZURE_174](./rules/CKV_AZURE_174.md) | CRITICAL (9/10) | Ensure API management public access is disabled |
| [CKV_AZURE_175](./rules/CKV_AZURE_175.md) | LOW (2/10) | Ensure Web PubSub uses a SKU with an SLA |
| [CKV_AZURE_176](./rules/CKV_AZURE_176.md) | MEDIUM (5.0/10) | Ensure Web PubSub uses managed identities to access Azure resources |
| [CKV_AZURE_177](./rules/CKV_AZURE_177.md) | MEDIUM (5.0/10) | Ensure Windows VM enables automatic updates |
| [CKV_AZURE_178](./rules/CKV_AZURE_178.md) | HIGH (7.5/10) | Ensure linux VM enables SSH with keys for secure communication |
| [CKV_AZURE_179](./rules/CKV_AZURE_179.md) | LOW (2.0/10) | Ensure VM agent is installed |
| [CKV_AZURE_180](./rules/CKV_AZURE_180.md) | LOW (2.0/10) | Ensure that data explorer uses Sku with an SLA |
| [CKV_AZURE_181](./rules/CKV_AZURE_181.md) | MEDIUM (5.0/10) | Ensure that data explorer/Kusto uses managed identities to access Azure resources securely |
| [CKV_AZURE_182](./rules/CKV_AZURE_182.md) | LOW (2.5/10) | Ensure that VNET has at least 2 connected DNS Endpoints |
| [CKV_AZURE_183](./rules/CKV_AZURE_183.md) | MEDIUM (4.5/10) | Ensure that VNET uses local DNS addresses |
| [CKV_AZURE_184](./rules/CKV_AZURE_184.md) | HIGH (7.5/10) | Ensure 'local_auth_enabled' is set to 'False' |
| [CKV_AZURE_185](./rules/CKV_AZURE_185.md) | CRITICAL (9/10) | Ensure 'Public Access' is not Enabled for App configuration |
| [CKV_AZURE_186](./rules/CKV_AZURE_186.md) | MEDIUM (5.0/10) | Ensure App configuration encryption block is set |
| [CKV_AZURE_187](./rules/CKV_AZURE_187.md) | MEDIUM (5.0/10) | Ensure App configuration purge protection is enabled |
| [CKV_AZURE_188](./rules/CKV_AZURE_188.md) | LOW (2.0/10) | Ensure App configuration Sku is standard |
| [CKV_AZURE_189](./rules/CKV_AZURE_189.md) | CRITICAL (9.5/10) | Ensure that Azure Key Vault disables public network access |
| [CKV_AZURE_190](./rules/CKV_AZURE_190.md) | CRITICAL (9/10) | Ensure that Storage blobs restrict public access |
| [CKV_AZURE_191](./rules/CKV_AZURE_191.md) | MEDIUM (5.0/10) | Ensure that Managed identity provider is enabled for Azure Event Grid Topic |
| [CKV_AZURE_192](./rules/CKV_AZURE_192.md) | MEDIUM (5.0/10) | Ensure that Azure Event Grid Topic local Authentication is disabled |
| [CKV_AZURE_193](./rules/CKV_AZURE_193.md) | CRITICAL (9/10) | Ensure public network access is disabled for Azure Event Grid Topic |
| [CKV_AZURE_194](./rules/CKV_AZURE_194.md) | MEDIUM (5.0/10) | Ensure that Managed identity provider is enabled for Azure Event Grid Domain |
| [CKV_AZURE_195](./rules/CKV_AZURE_195.md) | MEDIUM (5.0/10) | Ensure that Azure Event Grid Domain local Authentication is disabled |
| [CKV_AZURE_196](./rules/CKV_AZURE_196.md) | LOW (2/10) | Ensure that SignalR uses a Paid Sku for its SLA |
| [CKV_AZURE_197](./rules/CKV_AZURE_197.md) | MEDIUM (5/10) | Ensure the Azure CDN disables the HTTP endpoint |
| [CKV_AZURE_198](./rules/CKV_AZURE_198.md) | MEDIUM (5.5/10) | Ensure the Azure CDN enables the HTTPS endpoint |
| [CKV_AZURE_199](./rules/CKV_AZURE_199.md) | MEDIUM (5.0/10) | Ensure that Azure Service Bus uses double encryption |
| [CKV_AZURE_200](./rules/CKV_AZURE_200.md) | HIGH (7/10) | Ensure the Azure CDN endpoint is using the latest version of TLS encryption |
| [CKV_AZURE_201](./rules/CKV_AZURE_201.md) | MEDIUM (5.0/10) | Ensure that Azure Service Bus uses a customer-managed key to encrypt data |
| [CKV_AZURE_202](./rules/CKV_AZURE_202.md) | MEDIUM (5.0/10) | Ensure that Managed identity provider is enabled for Azure Service Bus |
| [CKV_AZURE_203](./rules/CKV_AZURE_203.md) | LOW (2.0/10) | Ensure Azure Service Bus Local Authentication is disabled |
| [CKV_AZURE_204](./rules/CKV_AZURE_204.md) | HIGH (7.5/10) | Ensure 'public network access enabled' is set to 'False' for Azure Service Bus |
| [CKV_AZURE_205](./rules/CKV_AZURE_205.md) | HIGH (7/10) | Ensure Azure Service Bus is using the latest version of TLS encryption |
| [CKV_AZURE_206](./rules/CKV_AZURE_206.md) | LOW (2.0/10) | Ensure that Storage Accounts use replication |
| [CKV_AZURE_207](./rules/CKV_AZURE_207.md) | MEDIUM (5.0/10) | Ensure Azure Cognitive Search service uses managed identities to access Azure resources |
| [CKV_AZURE_208](./rules/CKV_AZURE_208.md) | LOW (2.0/10) | Ensure that Azure Cognitive Search maintains SLA for index updates |
| [CKV_AZURE_209](./rules/CKV_AZURE_209.md) | LOW (2.0/10) | Ensure that Azure Cognitive Search maintains SLA for search index queries |
| [CKV_AZURE_210](./rules/CKV_AZURE_210.md) | CRITICAL (8.5/10) | Ensure Azure Cognitive Search service allowed IPS does not give public Access |
| [CKV_AZURE_211](./rules/CKV_AZURE_211.md) | LOW (2.0/10) | Ensure App Service plan suitable for production use |
| [CKV_AZURE_212](./rules/CKV_AZURE_212.md) | MEDIUM (4.5/10) | Ensure App Service has a minimum number of instances for failover |
| [CKV_AZURE_213](./rules/CKV_AZURE_213.md) | LOW (2.0/10) | Ensure that App Service configures health check |
| [CKV_AZURE_214](./rules/CKV_AZURE_214.md) | LOW (2.0/10) | Ensure App Service is set to be always on |
| [CKV_AZURE_215](./rules/CKV_AZURE_215.md) | HIGH (7.5/10) | Ensure API management backend uses https |
| [CKV_AZURE_216](./rules/CKV_AZURE_216.md) | HIGH (7/10) | Ensure DenyIntelMode is set to Deny for Azure Firewalls |
| [CKV_AZURE_217](./rules/CKV_AZURE_217.md) | HIGH (7.5/10) | Ensure Azure Application gateways listener that allow connection requests over HTTP |
| [CKV_AZURE_218](./rules/CKV_AZURE_218.md) | HIGH (7.5/10) | Ensure Application Gateway defines secure protocols for in transit communication |
| [CKV_AZURE_219](./rules/CKV_AZURE_219.md) | MEDIUM (5/10) | Ensure Firewall defines a firewall policy |
| [CKV_AZURE_220](./rules/CKV_AZURE_220.md) | HIGH (7.5/10) | Ensure Firewall policy has IDPS mode as deny |
| [CKV_AZURE_221](./rules/CKV_AZURE_221.md) | HIGH (7.5/10) | Ensure that Azure Function App public network access is disabled |
| [CKV_AZURE_222](./rules/CKV_AZURE_222.md) | HIGH (7.5/10) | Ensure that Azure Web App public network access is disabled |
| [CKV_AZURE_223](./rules/CKV_AZURE_223.md) | HIGH (7/10) | Ensure Event Hub Namespace uses at least TLS 1.2 |
| [CKV_AZURE_224](./rules/CKV_AZURE_224.md) | MEDIUM (5.0/10) | Ensure that the Ledger feature is enabled on database that requires cryptographic proof and nonrepudiation of data integrity |
| [CKV_AZURE_225](./rules/CKV_AZURE_225.md) | MEDIUM (5.0/10) | Ensure the App Service Plan is zone redundant |
| [CKV_AZURE_226](./rules/CKV_AZURE_226.md) | MEDIUM (5.0/10) | Ensure ephemeral disks are used for OS disks |
| [CKV_AZURE_227](./rules/CKV_AZURE_227.md) | HIGH (7.5/10) | Ensure that the AKS cluster encrypt temp disks, caches, and data flows between Compute and Storage resources |
| [CKV_AZURE_228](./rules/CKV_AZURE_228.md) | MEDIUM (5.0/10) | Ensure the Azure Event Hub Namespace is zone redundant |
| [CKV_AZURE_229](./rules/CKV_AZURE_229.md) | HIGH (7.5/10) | Ensure the Azure SQL Database Namespace is zone redundant |
| [CKV_AZURE_230](./rules/CKV_AZURE_230.md) | HIGH (7.5/10) | Standard Replication should be enabled |
| [CKV_AZURE_231](./rules/CKV_AZURE_231.md) | MEDIUM (5.0/10) | Ensure App Service Environment is zone redundant |
| [CKV_AZURE_232](./rules/CKV_AZURE_232.md) | HIGH (7.5/10) | Ensure that only critical system pods run on system nodes |
| [CKV_AZURE_233](./rules/CKV_AZURE_233.md) | LOW (2.0/10) | Ensure Azure Container Registry (ACR) is zone redundant |
| [CKV_AZURE_234](./rules/CKV_AZURE_234.md) | MEDIUM (5.0/10) | Ensure that Azure Defender for cloud is set to On for Resource Manager |
| [CKV_AZURE_235](./rules/CKV_AZURE_235.md) | CRITICAL (9/10) | Ensure that Azure container environment variables are configured with secure values only |
| [CKV_AZURE_236](./rules/CKV_AZURE_236.md) | LOW (2.0/10) | Ensure that Cognitive Services accounts disable local authentication |
| [CKV_AZURE_237](./rules/CKV_AZURE_237.md) | LOW (2.0/10) | Ensure dedicated data endpoints are enabled. |
| [CKV_AZURE_238](./rules/CKV_AZURE_238.md) | LOW (2.0/10) | Ensure that all Azure Cognitive Services accounts are configured with a managed identity |
| [CKV_AZURE_239](./rules/CKV_AZURE_239.md) | MEDIUM (5.0/10) | Ensure Azure Synapse Workspace administrator login password is not exposed |
| [CKV_AZURE_240](./rules/CKV_AZURE_240.md) | LOW (2.0/10) | Ensure Azure Synapse Workspace is encrypted with a CMK |
| [CKV_AZURE_241](./rules/CKV_AZURE_241.md) | LOW (2.0/10) | Ensure Synapse SQL pools are encrypted |
| [CKV_AZURE_242](./rules/CKV_AZURE_242.md) | LOW (2.0/10) | Ensure isolated compute is enabled for Synapse Spark pools |
| [CKV_AZURE_243](./rules/CKV_AZURE_243.md) | MEDIUM (5.0/10) | Ensure Azure Machine learning workspace is configured with private endpoint |
| [CKV_AZURE_244](./rules/CKV_AZURE_244.md) | LOW (2.0/10) | Avoid the use of local users for Azure Storage unless necessary |
| [CKV_AZURE_245](./rules/CKV_AZURE_245.md) | HIGH (7.5/10) | Ensure that Azure Container group is deployed into virtual network |
| [CKV_AZURE_246](./rules/CKV_AZURE_246.md) | MEDIUM (5.5/10) | Ensure Azure AKS cluster HTTP application routing is disabled |
| [CKV_AZURE_247](./rules/CKV_AZURE_247.md) | HIGH (7.5/10) | Ensure that Azure Cognitive Services account hosted with OpenAI is configured with data loss prevention |
| [CKV_AZURE_248](./rules/CKV_AZURE_248.md) | HIGH (7.5/10) | Ensure that if Azure Batch account public network access in case 'enabled' then its account access must be 'deny' |
| [CKV_AZURE_249](./rules/CKV_AZURE_249.md) | HIGH (7.5/10) | Ensure Azure GitHub Actions OIDC trust policy is configured securely |
| [CKV_AZURE_250](./rules/CKV_AZURE_250.md) | HIGH (7.5/10) | Ensure Storage Sync Service is not configured with overly permissive network access |
| [CKV_AZURE_251](./rules/CKV_AZURE_251.md) | HIGH (7.5/10) | Ensure Azure Virtual Machine disks are configured without public network access |

## AZUREPIPELINES

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_AZUREPIPELINES_1](./rules/CKV_AZUREPIPELINES_1.md) | MEDIUM (5.5/10) | Ensure container job uses a non latest version tag |
| [CKV_AZUREPIPELINES_2](./rules/CKV_AZUREPIPELINES_2.md) | MEDIUM (6/10) | Ensure container job uses a version digest |
| [CKV_AZUREPIPELINES_3](./rules/CKV_AZUREPIPELINES_3.md) | HIGH (7/10) | Ensure set variable is not marked as a secret |
| [CKV_AZUREPIPELINES_5](./rules/CKV_AZUREPIPELINES_5.md) | LOW (3/10) | Detecting image usages in azure pipelines workflows |

## BCW

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_BCW_1](./rules/CKV_BCW_1.md) | CRITICAL (9.5/10) | Ensure no hard coded API token exist in the provider |

## BITBUCKET

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_BITBUCKET_1](./rules/CKV_BITBUCKET_1.md) | MEDIUM (5.0/10) | Merge requests should require at least 2 approvals |

## BITBUCKETPIPELINES

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_BITBUCKETPIPELINES_1](./rules/CKV_BITBUCKETPIPELINES_1.md) | LOW (3/10) | Ensure the pipeline image uses a non latest version tag |

## CIRCLECIPIPELINES

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_CIRCLECIPIPELINES_1](./rules/CKV_CIRCLECIPIPELINES_1.md) | LOW (3/10) | Ensure the pipeline image uses a non latest version tag |
| [CKV_CIRCLECIPIPELINES_2](./rules/CKV_CIRCLECIPIPELINES_2.md) | MEDIUM (4.5/10) | Ensure the pipeline image version is referenced via hash not arbitrary tag. |
| [CKV_CIRCLECIPIPELINES_3](./rules/CKV_CIRCLECIPIPELINES_3.md) | MEDIUM (6/10) | Ensure mutable development orbs are not used. |
| [CKV_CIRCLECIPIPELINES_4](./rules/CKV_CIRCLECIPIPELINES_4.md) | MEDIUM (6/10) | Ensure unversioned volatile orbs are not used. |
| [CKV_CIRCLECIPIPELINES_5](./rules/CKV_CIRCLECIPIPELINES_5.md) | CRITICAL (9.3/10) | Suspicious use of netcat with IP address |
| [CKV_CIRCLECIPIPELINES_6](./rules/CKV_CIRCLECIPIPELINES_6.md) | CRITICAL (9.1/10) | Ensure run commands are not vulnerable to shell injection |
| [CKV_CIRCLECIPIPELINES_7](./rules/CKV_CIRCLECIPIPELINES_7.md) | HIGH (7.8/10) | Suspicious use of curl in run task |
| [CKV_CIRCLECIPIPELINES_8](./rules/CKV_CIRCLECIPIPELINES_8.md) | LOW (1/10) | Detecting image usages in circleci pipelines |

## DIO

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_DIO_1](./rules/CKV_DIO_1.md) | MEDIUM (4.5/10) | Ensure the Spaces bucket has versioning enabled |
| [CKV_DIO_2](./rules/CKV_DIO_2.md) | MEDIUM (5.5/10) | Ensure the droplet specifies an SSH key |
| [CKV_DIO_3](./rules/CKV_DIO_3.md) | HIGH (7.5/10) | Ensure the Spaces bucket is private |
| [CKV_DIO_4](./rules/CKV_DIO_4.md) | HIGH (8/10) | Ensure the firewall ingress is not wide open |

## DOCKER

| Rule ID | Severity | Description |
|---|---|---|
| [CKV2_DOCKER_1](./rules/CKV2_DOCKER_1.md) | LOW (2.0/10) | Ensure that sudo isn't used |
| [CKV_DOCKER_1](./rules/CKV_DOCKER_1.md) | MEDIUM (5/10) | Ensure port 22 is not exposed |
| [CKV2_DOCKER_2](./rules/CKV2_DOCKER_2.md) | HIGH (7.5/10) | Ensure that certificate validation isn't disabled with curl |
| [CKV_DOCKER_2](./rules/CKV_DOCKER_2.md) | LOW (2.0/10) | Ensure that HEALTHCHECK instructions have been added to container images |
| [CKV2_DOCKER_3](./rules/CKV2_DOCKER_3.md) | HIGH (7.5/10) | Ensure that certificate validation isn't disabled with wget |
| [CKV_DOCKER_3](./rules/CKV_DOCKER_3.md) | LOW (2.0/10) | Ensure that a user for the container has been created |
| [CKV2_DOCKER_4](./rules/CKV2_DOCKER_4.md) | HIGH (7.5/10) | Ensure that certificate validation isn't disabled with the pip '--trusted-host' option |
| [CKV_DOCKER_4](./rules/CKV_DOCKER_4.md) | LOW (2.0/10) | Ensure that COPY is used instead of ADD in Dockerfiles |
| [CKV2_DOCKER_5](./rules/CKV2_DOCKER_5.md) | HIGH (7.5/10) | Ensure that certificate validation isn't disabled with the PYTHONHTTPSVERIFY environment variable |
| [CKV_DOCKER_5](./rules/CKV_DOCKER_5.md) | LOW (2.0/10) | Ensure update instructions are not use alone in the Dockerfile |
| [CKV2_DOCKER_6](./rules/CKV2_DOCKER_6.md) | HIGH (7.5/10) | Ensure that certificate validation isn't disabled with the NODE_TLS_REJECT_UNAUTHORIZED environment variable |
| [CKV_DOCKER_6](./rules/CKV_DOCKER_6.md) | LOW (2.0/10) | Ensure that LABEL maintainer is used instead of MAINTAINER (deprecated) |
| [CKV2_DOCKER_7](./rules/CKV2_DOCKER_7.md) | MEDIUM (5.0/10) | Ensure that packages with untrusted or missing signatures are not used by apk via the '--allow-untrusted' option |
| [CKV_DOCKER_7](./rules/CKV_DOCKER_7.md) | LOW (2.0/10) | Ensure the base image uses a non latest version tag |
| [CKV2_DOCKER_8](./rules/CKV2_DOCKER_8.md) | MEDIUM (5.0/10) | Ensure that packages with untrusted or missing signatures are not used by apt-get via the '--allow-unauthenticated' option |
| [CKV_DOCKER_8](./rules/CKV_DOCKER_8.md) | LOW (2.0/10) | Ensure the last USER is not root |
| [CKV2_DOCKER_9](./rules/CKV2_DOCKER_9.md) | MEDIUM (5.0/10) | Ensure that packages with untrusted or missing GPG signatures are not used by dnf, tdnf, or yum via the '--nogpgcheck' option |
| [CKV_DOCKER_9](./rules/CKV_DOCKER_9.md) | LOW (2.0/10) | Ensure that APT isn't used |
| [CKV2_DOCKER_10](./rules/CKV2_DOCKER_10.md) | HIGH (7.5/10) | Ensure that packages with untrusted or missing signatures are not used by rpm via the '--nodigest', '--nosignature', '--noverify', or '--nofiledigest' options |
| [CKV_DOCKER_10](./rules/CKV_DOCKER_10.md) | LOW (2.0/10) | Ensure that WORKDIR values are absolute paths |
| [CKV2_DOCKER_11](./rules/CKV2_DOCKER_11.md) | HIGH (7.5/10) | Ensure that the '--force-yes' option is not used, as it disables signature validation and allows packages to be downgraded which can leave the system in a broken or inconsistent state |
| [CKV_DOCKER_11](./rules/CKV_DOCKER_11.md) | LOW (2.0/10) | Ensure From Alias are unique for multistage builds. |
| [CKV2_DOCKER_12](./rules/CKV2_DOCKER_12.md) | HIGH (7.5/10) | Ensure that certificate validation isn't disabled for npm via the 'NPM_CONFIG_STRICT_SSL' environment variable |
| [CKV2_DOCKER_13](./rules/CKV2_DOCKER_13.md) | HIGH (7.5/10) | Ensure that certificate validation isn't disabled for npm or yarn by setting the option strict-ssl to false |
| [CKV2_DOCKER_14](./rules/CKV2_DOCKER_14.md) | HIGH (7.5/10) | Ensure that certificate validation isn't disabled for git by setting the environment variable 'GIT_SSL_NO_VERIFY' to any value |
| [CKV2_DOCKER_15](./rules/CKV2_DOCKER_15.md) | HIGH (7.5/10) | Ensure that the yum and dnf package managers are not configured to disable SSL certificate validation via the 'sslverify' configuration option |
| [CKV2_DOCKER_16](./rules/CKV2_DOCKER_16.md) | MEDIUM (5.0/10) | Ensure that certificate validation isn't disabled with pip via the 'PIP_TRUSTED_HOST' environment variable |
| [CKV2_DOCKER_17](./rules/CKV2_DOCKER_17.md) | MEDIUM (5.0/10) | Ensure that 'chpasswd' is not used to set or remove passwords |

## GCP

| Rule ID | Severity | Description |
|---|---|---|
| [CKV2_GCP_1](./rules/CKV2_GCP_1.md) | LOW (2.0/10) | Ensure GKE clusters are not running using the Compute Engine default service account |
| [CKV_GCP_1](./rules/CKV_GCP_1.md) | LOW (2.0/10) | Ensure Stackdriver Logging is set to Enabled on Kubernetes Engine Clusters |
| [CKV2_GCP_2](./rules/CKV2_GCP_2.md) | MEDIUM (5.0/10) | Ensure legacy networks do not exist for a project |
| [CKV_GCP_2](./rules/CKV_GCP_2.md) | CRITICAL (9.3/10) | Ensure Google compute firewall ingress does not allow unrestricted ssh access |
| [CKV2_GCP_3](./rules/CKV2_GCP_3.md) | LOW (2.0/10) | Ensure that there are only GCP-managed service account keys for each service account |
| [CKV_GCP_3](./rules/CKV_GCP_3.md) | CRITICAL (9.3/10) | Ensure Google compute firewall ingress does not allow unrestricted rdp access |
| [CKV2_GCP_4](./rules/CKV2_GCP_4.md) | LOW (2.0/10) | Ensure that retention policies on log buckets are configured using Bucket Lock |
| [CKV_GCP_4](./rules/CKV_GCP_4.md) | HIGH (7.5/10) | Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites |
| [CKV2_GCP_5](./rules/CKV2_GCP_5.md) | LOW (2.0/10) | Ensure that Cloud Audit Logging is configured properly across all services and all users from a project |
| [CKV2_GCP_6](./rules/CKV2_GCP_6.md) | CRITICAL (9.1/10) | Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible |
| [CKV_GCP_6](./rules/CKV_GCP_6.md) | HIGH (7.5/10) | Ensure all Cloud SQL database instance requires all incoming connections to use SSL |
| [CKV2_GCP_7](./rules/CKV2_GCP_7.md) | LOW (2.0/10) | Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges |
| [CKV_GCP_7](./rules/CKV_GCP_7.md) | LOW (2.0/10) | Ensure Legacy Authorization is set to Disabled on Kubernetes Engine Clusters |
| [CKV2_GCP_8](./rules/CKV2_GCP_8.md) | CRITICAL (9.1/10) | Ensure that Cloud KMS Key Rings are not anonymously or publicly accessible |
| [CKV_GCP_8](./rules/CKV_GCP_8.md) | LOW (2.0/10) | Ensure Stackdriver Monitoring is set to Enabled on Kubernetes Engine Clusters |
| [CKV2_GCP_9](./rules/CKV2_GCP_9.md) | CRITICAL (9/10) | Ensure that Container Registry repositories are not anonymously or publicly accessible |
| [CKV_GCP_9](./rules/CKV_GCP_9.md) | LOW (2.0/10) | Ensure 'Automatic node repair' is enabled for Kubernetes Clusters |
| [CKV2_GCP_10](./rules/CKV2_GCP_10.md) | HIGH (7/10) | Ensure GCP Cloud Function HTTP trigger is secured |
| [CKV_GCP_10](./rules/CKV_GCP_10.md) | LOW (2.0/10) | Ensure 'Automatic node upgrade' is enabled for Kubernetes Clusters |
| [CKV2_GCP_11](./rules/CKV2_GCP_11.md) | LOW (2.0/10) | Ensure GCP GCR Container Vulnerability Scanning is enabled |
| [CKV_GCP_11](./rules/CKV_GCP_11.md) | CRITICAL (9/10) | Ensure that Cloud SQL database Instances are not open to the world |
| [CKV2_GCP_12](./rules/CKV2_GCP_12.md) | CRITICAL (9.5/10) | Ensure GCP compute firewall ingress does not allow unrestricted access to all ports |
| [CKV_GCP_12](./rules/CKV_GCP_12.md) | LOW (2.0/10) | Ensure Network Policy is enabled on Kubernetes Engine Clusters |
| [CKV2_GCP_13](./rules/CKV2_GCP_13.md) | LOW (2.0/10) | Ensure PostgreSQL database flag 'log_duration' is set to 'on' |
| [CKV_GCP_13](./rules/CKV_GCP_13.md) | LOW (2.0/10) | Ensure client certificate authentication to Kubernetes Engine Clusters is disabled |
| [CKV2_GCP_14](./rules/CKV2_GCP_14.md) | LOW (2.0/10) | Ensure PostgreSQL database flag 'log_executor_stats' is set to 'off' |
| [CKV_GCP_14](./rules/CKV_GCP_14.md) | HIGH (7.5/10) | Ensure all Cloud SQL database instance have backup configuration enabled |
| [CKV2_GCP_15](./rules/CKV2_GCP_15.md) | LOW (2.0/10) | Ensure PostgreSQL database flag 'log_parser_stats' is set to 'off' |
| [CKV_GCP_15](./rules/CKV_GCP_15.md) | CRITICAL (9.1/10) | Ensure that BigQuery datasets are not anonymously or publicly accessible |
| [CKV2_GCP_16](./rules/CKV2_GCP_16.md) | LOW (2.0/10) | Ensure PostgreSQL database flag 'log_planner_stats' is set to 'off' |
| [CKV_GCP_16](./rules/CKV_GCP_16.md) | MEDIUM (5/10) | Ensure that DNSSEC is enabled for Cloud DNS |
| [CKV2_GCP_17](./rules/CKV2_GCP_17.md) | LOW (2.0/10) | Ensure PostgreSQL database flag 'log_statement_stats' is set to 'off' |
| [CKV_GCP_17](./rules/CKV_GCP_17.md) | MEDIUM (4.5/10) | Ensure that RSASHA1 is not used for the zone-signing and key-signing keys in Cloud DNS DNSSEC |
| [CKV2_GCP_18](./rules/CKV2_GCP_18.md) | HIGH (7.5/10) | Ensure GCP network defines a firewall and does not use the default firewall |
| [CKV_GCP_18](./rules/CKV_GCP_18.md) | CRITICAL (9/10) | Ensure GKE Control Plane is not public |
| [CKV2_GCP_19](./rules/CKV2_GCP_19.md) | LOW (2.0/10) | Ensure GCP Kubernetes engine clusters have 'alpha cluster' feature disabled |
| [CKV2_GCP_20](./rules/CKV2_GCP_20.md) | LOW (2.0/10) | Ensure MySQL DB instance has point-in-time recovery backup configured |
| [CKV_GCP_20](./rules/CKV_GCP_20.md) | LOW (2.0/10) | Ensure master authorized networks is set to enabled in GKE clusters |
| [CKV2_GCP_21](./rules/CKV2_GCP_21.md) | MEDIUM (5.0/10) | Ensure Vertex AI instance disks are encrypted with a Customer Managed Key (CMK) |
| [CKV_GCP_21](./rules/CKV_GCP_21.md) | LOW (2.0/10) | Ensure Kubernetes Clusters are configured with Labels |
| [CKV2_GCP_22](./rules/CKV2_GCP_22.md) | MEDIUM (5.0/10) | Ensure Document AI Processors are encrypted with a Customer Managed Key (CMK) |
| [CKV_GCP_22](./rules/CKV_GCP_22.md) | LOW (2.0/10) | Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image |
| [CKV2_GCP_23](./rules/CKV2_GCP_23.md) | MEDIUM (5.0/10) | Ensure Document AI Warehouse Location is configured to use a Customer Managed Key (CMK) |
| [CKV_GCP_23](./rules/CKV_GCP_23.md) | LOW (2.0/10) | Ensure Kubernetes Cluster is created with Alias IP ranges enabled |
| [CKV2_GCP_24](./rules/CKV2_GCP_24.md) | MEDIUM (5.0/10) | Ensure Vertex AI endpoint uses a Customer Managed Key (CMK) |
| [CKV_GCP_24](./rules/CKV_GCP_24.md) | LOW (2.0/10) | Ensure PodSecurityPolicy controller is enabled on the Kubernetes Engine Clusters |
| [CKV2_GCP_25](./rules/CKV2_GCP_25.md) | MEDIUM (5.0/10) | Ensure Vertex AI featurestore uses a Customer Managed Key (CMK) |
| [CKV_GCP_25](./rules/CKV_GCP_25.md) | MEDIUM (5.0/10) | Ensure Kubernetes Cluster is created with Private cluster enabled |
| [CKV2_GCP_26](./rules/CKV2_GCP_26.md) | MEDIUM (5.0/10) | Ensure Vertex AI tensorboard uses a Customer Managed Key (CMK) |
| [CKV_GCP_26](./rules/CKV_GCP_26.md) | LOW (2.0/10) | Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network |
| [CKV2_GCP_27](./rules/CKV2_GCP_27.md) | MEDIUM (5.0/10) | Ensure Vertex AI workbench instance disks are encrypted with a Customer Managed Key (CMK) |
| [CKV_GCP_27](./rules/CKV_GCP_27.md) | MEDIUM (5.5/10) | Ensure that the default network does not exist in a project |
| [CKV2_GCP_28](./rules/CKV2_GCP_28.md) | MEDIUM (5.0/10) | Ensure Vertex AI workbench instances are private |
| [CKV_GCP_28](./rules/CKV_GCP_28.md) | CRITICAL (9.2/10) | Ensure that Cloud Storage bucket is not anonymously or publicly accessible |
| [CKV2_GCP_29](./rules/CKV2_GCP_29.md) | MEDIUM (5.0/10) | Ensure logging is enabled for Dialogflow agents |
| [CKV_GCP_29](./rules/CKV_GCP_29.md) | LOW (2.0/10) | Ensure that Cloud Storage buckets have uniform bucket-level access enabled |
| [CKV2_GCP_30](./rules/CKV2_GCP_30.md) | MEDIUM (5.0/10) | Ensure logging is enabled for Dialogflow CX agents |
| [CKV_GCP_30](./rules/CKV_GCP_30.md) | LOW (2.0/10) | Ensure that instances are not configured to use the default service account |
| [CKV2_GCP_31](./rules/CKV2_GCP_31.md) | MEDIUM (5.0/10) | Ensure logging is enabled for Dialogflow CX webhooks |
| [CKV_GCP_31](./rules/CKV_GCP_31.md) | MEDIUM (5.0/10) | Ensure that instances are not configured to use the default service account with full access to all Cloud APIs |
| [CKV2_GCP_32](./rules/CKV2_GCP_32.md) | HIGH (7/10) | Ensure TPU v2 is private |
| [CKV_GCP_32](./rules/CKV_GCP_32.md) | HIGH (7.5/10) | Ensure 'Block Project-wide SSH keys' is enabled for VM instances |
| [CKV2_GCP_33](./rules/CKV2_GCP_33.md) | MEDIUM (5.0/10) | Ensure Vertex AI endpoint is private |
| [CKV_GCP_33](./rules/CKV_GCP_33.md) | MEDIUM (5.5/10) | Ensure oslogin is enabled for a Project |
| [CKV2_GCP_34](./rules/CKV2_GCP_34.md) | MEDIUM (5.0/10) | Ensure Vertex AI index endpoint is private |
| [CKV_GCP_34](./rules/CKV_GCP_34.md) | MEDIUM (5/10) | Ensure that no instance in the project overrides the project setting for enabling OSLogin |
| [CKV2_GCP_35](./rules/CKV2_GCP_35.md) | MEDIUM (5.0/10) | Ensure Vertex AI runtime is encrypted with a Customer Managed Key (CMK) |
| [CKV_GCP_35](./rules/CKV_GCP_35.md) | HIGH (7.5/10) | Ensure 'Enable connecting to serial ports' is not enabled for VM Instance |
| [CKV2_GCP_36](./rules/CKV2_GCP_36.md) | MEDIUM (5.0/10) | Ensure Vertex AI runtime is private |
| [CKV_GCP_36](./rules/CKV_GCP_36.md) | HIGH (7/10) | Ensure that IP forwarding is not enabled on Instances |
| [CKV2_GCP_37](./rules/CKV2_GCP_37.md) | MEDIUM (5.0/10) | Ensure GCP compute regional forwarding rule does not use HTTP proxies with EXTERNAL load balancing scheme |
| [CKV_GCP_37](./rules/CKV_GCP_37.md) | LOW (2.0/10) | Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK) |
| [CKV2_GCP_38](./rules/CKV2_GCP_38.md) | MEDIUM (5.0/10) | Ensure GCP compute global forwarding rule does not use HTTP proxies with EXTERNAL load balancing scheme |
| [CKV_GCP_38](./rules/CKV_GCP_38.md) | HIGH (7.5/10) | Ensure VM disks for critical VMs are encrypted with Customer Supplied Encryption Keys (CSEK) |
| [CKV_GCP_39](./rules/CKV_GCP_39.md) | HIGH (7.5/10) | Ensure Compute instances are launched with Shielded VM enabled |
| [CKV_GCP_40](./rules/CKV_GCP_40.md) | HIGH (8/10) | Ensure that Compute instances do not have public IP addresses |
| [CKV_GCP_41](./rules/CKV_GCP_41.md) | HIGH (7.5/10) | Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level |
| [CKV_GCP_42](./rules/CKV_GCP_42.md) | HIGH (7.5/10) | Ensure that Service Account has no Admin privileges |
| [CKV_GCP_43](./rules/CKV_GCP_43.md) | LOW (2.0/10) | Ensure KMS encryption keys are rotated within a period of 90 days |
| [CKV_GCP_44](./rules/CKV_GCP_44.md) | HIGH (7.5/10) | Ensure no roles that enable to impersonate and manage all service accounts are used at a folder level |
| [CKV_GCP_45](./rules/CKV_GCP_45.md) | HIGH (7.5/10) | Ensure no roles that enable to impersonate and manage all service accounts are used at an organization level |
| [CKV_GCP_46](./rules/CKV_GCP_46.md) | HIGH (7.5/10) | Ensure Default Service account is not used at a project level |
| [CKV_GCP_47](./rules/CKV_GCP_47.md) | HIGH (7.5/10) | Ensure default service account is not used at an organization level |
| [CKV_GCP_48](./rules/CKV_GCP_48.md) | HIGH (7.5/10) | Ensure Default Service account is not used at a folder level |
| [CKV_GCP_49](./rules/CKV_GCP_49.md) | LOW (2.0/10) | Ensure roles do not impersonate or manage Service Accounts used at project level |
| [CKV_GCP_50](./rules/CKV_GCP_50.md) | LOW (2.0/10) | Ensure MySQL database 'local_infile' flag is set to 'off' |
| [CKV_GCP_51](./rules/CKV_GCP_51.md) | LOW (2.0/10) | Ensure PostgreSQL database 'log_checkpoints' flag is set to 'on' |
| [CKV_GCP_52](./rules/CKV_GCP_52.md) | LOW (2.0/10) | Ensure PostgreSQL database 'log_connections' flag is set to 'on' |
| [CKV_GCP_53](./rules/CKV_GCP_53.md) | LOW (2.0/10) | Ensure PostgreSQL database 'log_disconnections' flag is set to 'on' |
| [CKV_GCP_54](./rules/CKV_GCP_54.md) | LOW (2.0/10) | Ensure PostgreSQL database 'log_lock_waits' flag is set to 'on' |
| [CKV_GCP_55](./rules/CKV_GCP_55.md) | LOW (2.0/10) | Ensure PostgreSQL database 'log_min_messages' flag is set to a valid value |
| [CKV_GCP_56](./rules/CKV_GCP_56.md) | LOW (2.0/10) | Ensure PostgreSQL database 'log_temp_files flag is set to '0' |
| [CKV_GCP_57](./rules/CKV_GCP_57.md) | LOW (2.0/10) | Ensure PostgreSQL database 'log_min_duration_statement' flag is set to '-1' |
| [CKV_GCP_58](./rules/CKV_GCP_58.md) | LOW (2.0/10) | Ensure SQL database 'cross db ownership chaining' flag is set to 'off' |
| [CKV_GCP_59](./rules/CKV_GCP_59.md) | LOW (2.0/10) | Ensure SQL database 'contained database authentication' flag is set to 'off' |
| [CKV_GCP_60](./rules/CKV_GCP_60.md) | HIGH (8/10) | Ensure Cloud SQL database does not have public IP |
| [CKV_GCP_61](./rules/CKV_GCP_61.md) | LOW (2.0/10) | Enable VPC Flow Logs and Intranode Visibility |
| [CKV_GCP_62](./rules/CKV_GCP_62.md) | LOW (2.0/10) | Bucket should log access |
| [CKV_GCP_63](./rules/CKV_GCP_63.md) | LOW (2.0/10) | Bucket should not log to itself |
| [CKV_GCP_64](./rules/CKV_GCP_64.md) | LOW (2.0/10) | Ensure clusters are created with Private Nodes |
| [CKV_GCP_65](./rules/CKV_GCP_65.md) | LOW (2.0/10) | Manage Kubernetes RBAC users with Google Groups for GKE |
| [CKV_GCP_66](./rules/CKV_GCP_66.md) | LOW (2.0/10) | Ensure use of Binary Authorization |
| [CKV_GCP_68](./rules/CKV_GCP_68.md) | LOW (2.0/10) | Ensure Secure Boot for Shielded GKE Nodes is Enabled |
| [CKV_GCP_69](./rules/CKV_GCP_69.md) | LOW (2.0/10) | Ensure the GKE Metadata Server is Enabled |
| [CKV_GCP_70](./rules/CKV_GCP_70.md) | LOW (2.0/10) | Ensure the GKE Release Channel is set |
| [CKV_GCP_71](./rules/CKV_GCP_71.md) | LOW (2.0/10) | Ensure Shielded GKE Nodes are Enabled |
| [CKV_GCP_72](./rules/CKV_GCP_72.md) | LOW (2.0/10) | Ensure Integrity Monitoring for Shielded GKE Nodes is Enabled |
| [CKV_GCP_73](./rules/CKV_GCP_73.md) | MEDIUM (5.0/10) | Ensure Cloud Armor prevents message lookup in Log4j2 (CVE-2021-44228 / Log4Shell) |
| [CKV_GCP_74](./rules/CKV_GCP_74.md) | MEDIUM (4.5/10) | Ensure that private_ip_google_access is enabled for Subnet |
| [CKV_GCP_75](./rules/CKV_GCP_75.md) | CRITICAL (9/10) | Ensure Google compute firewall ingress does not allow unrestricted FTP access |
| [CKV_GCP_76](./rules/CKV_GCP_76.md) | MEDIUM (4.5/10) | Ensure that Private Google Access is enabled for IPv6 |
| [CKV_GCP_77](./rules/CKV_GCP_77.md) | HIGH (7/10) | Ensure Google compute firewall ingress does not allow unrestricted access on the FTP-data port |
| [CKV_GCP_78](./rules/CKV_GCP_78.md) | LOW (2.0/10) | Ensure Cloud storage has versioning enabled |
| [CKV_GCP_79](./rules/CKV_GCP_79.md) | LOW (2.0/10) | Ensure SQL database is using latest Major version |
| [CKV_GCP_80](./rules/CKV_GCP_80.md) | LOW (2.0/10) | Ensure Big Query Tables are encrypted with Customer Supplied/Managed Encryption Keys (CMEK) |
| [CKV_GCP_81](./rules/CKV_GCP_81.md) | LOW (2.0/10) | Ensure Big Query Datasets are encrypted with Customer Supplied/Managed Encryption Keys (CMEK) |
| [CKV_GCP_82](./rules/CKV_GCP_82.md) | LOW (2.0/10) | Ensure KMS keys are protected from deletion |
| [CKV_GCP_83](./rules/CKV_GCP_83.md) | LOW (2.0/10) | Ensure PubSub Topics are encrypted with Customer Supplied Encryption Keys (CSEK) |
| [CKV_GCP_84](./rules/CKV_GCP_84.md) | LOW (2.0/10) | Ensure Artifact Registry Repositories are encrypted with Customer Supplied Encryption Keys (CSEK) |
| [CKV_GCP_85](./rules/CKV_GCP_85.md) | LOW (2.0/10) | Ensure Big Table Instances are encrypted with Customer Supplied Encryption Keys (CSEK) |
| [CKV_GCP_86](./rules/CKV_GCP_86.md) | HIGH (7/10) | Ensure Cloud build workers are private |
| [CKV_GCP_87](./rules/CKV_GCP_87.md) | HIGH (7/10) | Ensure Data fusion instances are private |
| [CKV_GCP_88](./rules/CKV_GCP_88.md) | CRITICAL (9/10) | Ensure Google compute firewall ingress does not allow unrestricted mysql access |
| [CKV_GCP_89](./rules/CKV_GCP_89.md) | HIGH (7/10) | Ensure Vertex AI instances are private |
| [CKV_GCP_90](./rules/CKV_GCP_90.md) | LOW (2.0/10) | Ensure data flow jobs are encrypted with Customer Supplied Encryption Keys (CSEK) |
| [CKV_GCP_91](./rules/CKV_GCP_91.md) | LOW (2.0/10) | Ensure Dataproc cluster is encrypted with Customer Supplied Encryption Keys (CSEK) |
| [CKV_GCP_92](./rules/CKV_GCP_92.md) | LOW (2.0/10) | Ensure Vertex AI datasets uses a CMK (Customer Managed Key) |
| [CKV_GCP_93](./rules/CKV_GCP_93.md) | LOW (2.0/10) | Ensure Spanner Database is encrypted with Customer Supplied Encryption Keys (CSEK) |
| [CKV_GCP_94](./rules/CKV_GCP_94.md) | HIGH (7/10) | Ensure Dataflow jobs are private |
| [CKV_GCP_95](./rules/CKV_GCP_95.md) | MEDIUM (5.0/10) | Ensure Memorystore for Redis has AUTH enabled |
| [CKV_GCP_96](./rules/CKV_GCP_96.md) | LOW (2.0/10) | Ensure Vertex AI Metadata Store uses a CMK (Customer Managed Key) |
| [CKV_GCP_97](./rules/CKV_GCP_97.md) | LOW (2.0/10) | Ensure Memorystore for Redis uses intransit encryption |
| [CKV_GCP_98](./rules/CKV_GCP_98.md) | CRITICAL (8.5/10) | Ensure that Dataproc clusters are not anonymously or publicly accessible |
| [CKV_GCP_99](./rules/CKV_GCP_99.md) | HIGH (7.5/10) | Ensure that Pub/Sub Topics are not anonymously or publicly accessible |
| [CKV_GCP_100](./rules/CKV_GCP_100.md) | CRITICAL (9/10) | Ensure that BigQuery Tables are not anonymously or publicly accessible |
| [CKV_GCP_101](./rules/CKV_GCP_101.md) | HIGH (7.5/10) | Ensure that Artifact Registry repositories are not anonymously or publicly accessible |
| [CKV_GCP_102](./rules/CKV_GCP_102.md) | HIGH (7.5/10) | Ensure that GCP Cloud Run services are not anonymously or publicly accessible |
| [CKV_GCP_103](./rules/CKV_GCP_103.md) | HIGH (7.5/10) | Ensure Dataproc Clusters do not have public IPs |
| [CKV_GCP_104](./rules/CKV_GCP_104.md) | LOW (2.0/10) | Ensure Datafusion has stack driver logging enabled |
| [CKV_GCP_105](./rules/CKV_GCP_105.md) | LOW (2.0/10) | Ensure Datafusion has stack driver monitoring enabled |
| [CKV_GCP_106](./rules/CKV_GCP_106.md) | HIGH (7/10) | Ensure Google compute firewall ingress does not allow unrestricted http port 80 access |
| [CKV_GCP_107](./rules/CKV_GCP_107.md) | HIGH (7.5/10) | Cloud functions should not be public |
| [CKV_GCP_108](./rules/CKV_GCP_108.md) | LOW (2.0/10) | Ensure hostnames are logged for GCP PostgreSQL databases |
| [CKV_GCP_109](./rules/CKV_GCP_109.md) | LOW (2.0/10) | Ensure the GCP PostgreSQL database log levels are set to ERROR or lower |
| [CKV_GCP_110](./rules/CKV_GCP_110.md) | LOW (2.0/10) | Ensure pgAudit is enabled for your GCP PostgreSQL database |
| [CKV_GCP_111](./rules/CKV_GCP_111.md) | MEDIUM (5.0/10) | Ensure GCP PostgreSQL logs SQL statements |
| [CKV_GCP_112](./rules/CKV_GCP_112.md) | HIGH (7.5/10) | Ensure KMS policy should not allow public access |
| [CKV_GCP_113](./rules/CKV_GCP_113.md) | HIGH (7.5/10) | Ensure IAM policy should not define public access |
| [CKV_GCP_114](./rules/CKV_GCP_114.md) | HIGH (8/10) | Ensure public access prevention is enforced on Cloud Storage bucket |
| [CKV_GCP_115](./rules/CKV_GCP_115.md) | HIGH (7.5/10) | Ensure basic roles are not used at organization level. |
| [CKV_GCP_116](./rules/CKV_GCP_116.md) | MEDIUM (5.0/10) | Ensure basic roles are not used at folder level. |
| [CKV_GCP_117](./rules/CKV_GCP_117.md) | HIGH (7.5/10) | Ensure basic roles are not used at project level. |
| [CKV_GCP_118](./rules/CKV_GCP_118.md) | HIGH (7.5/10) | Ensure IAM workload identity pool provider is restricted |
| [CKV_GCP_119](./rules/CKV_GCP_119.md) | MEDIUM (5.0/10) | Ensure Spanner Database has deletion protection enabled |
| [CKV_GCP_120](./rules/CKV_GCP_120.md) | HIGH (7.5/10) | Ensure Spanner Database has drop protection enabled |
| [CKV_GCP_121](./rules/CKV_GCP_121.md) | MEDIUM (5.0/10) | Ensure BigQuery tables have deletion protection enabled |
| [CKV_GCP_122](./rules/CKV_GCP_122.md) | MEDIUM (5.0/10) | Ensure Big Table Instances have deletion protection enabled |
| [CKV_GCP_123](./rules/CKV_GCP_123.md) | LOW (2.0/10) | GKE Don't Use NodePools in the Cluster configuration |
| [CKV_GCP_124](./rules/CKV_GCP_124.md) | HIGH (7.6/10) | Ensure GCP Cloud Function is not configured with overly permissive Ingress setting |
| [CKV_GCP_125](./rules/CKV_GCP_125.md) | HIGH (7.5/10) | Ensure GCP GitHub Actions OIDC trust policy is configured securely |
| [CKV_GCP_126](./rules/CKV_GCP_126.md) | LOW (2.0/10) | Ensure Vertex AI Notebook instances are launched with Shielded VM enabled |
| [CKV_GCP_127](./rules/CKV_GCP_127.md) | LOW (2.0/10) | Ensure Integrity Monitoring for Shielded Vertex AI Notebook Instances is Enabled |

## GHA

| Rule ID | Severity | Description |
|---|---|---|
| [CKV2_GHA_1](./rules/CKV2_GHA_1.md) | HIGH (7.5/10) | Ensure top-level permissions are not set to write-all |
| [CKV_GHA_1](./rules/CKV_GHA_1.md) | HIGH (8/10) | Ensure ACTIONS_ALLOW_UNSECURE_COMMANDS isn't true on environment variables |
| [CKV_GHA_2](./rules/CKV_GHA_2.md) | CRITICAL (9/10) | Ensure run commands are not vulnerable to shell injection |
| [CKV_GHA_3](./rules/CKV_GHA_3.md) | CRITICAL (8.5/10) | Suspicious use of curl with secrets |
| [CKV_GHA_4](./rules/CKV_GHA_4.md) | CRITICAL (9.5/10) | Suspicious use of netcat with IP address |
| [CKV_GHA_5](./rules/CKV_GHA_5.md) | MEDIUM (5/10) | Found artifact build without evidence of cosign sign execution in pipeline |
| [CKV_GHA_6](./rules/CKV_GHA_6.md) | MEDIUM (4/10) | Found artifact build without evidence of cosign sbom attestation in pipeline |
| [CKV_GHA_7](./rules/CKV_GHA_7.md) | HIGH (7/10) | GitHub Actions workflow_dispatch inputs MUST be empty |

## GIT

| Rule ID | Severity | Description |
|---|---|---|
| [CKV2_GIT_1](./rules/CKV2_GIT_1.md) | MEDIUM (5.5/10) | Ensure each Repository has branch protection associated |
| [CKV_GIT_1](./rules/CKV_GIT_1.md) | HIGH (7.5/10) | Ensure GitHub repository is Private |
| [CKV_GIT_2](./rules/CKV_GIT_2.md) | HIGH (7/10) | Ensure GitHub repository webhooks are using HTTPS |
| [CKV_GIT_3](./rules/CKV_GIT_3.md) | LOW (2.0/10) | Ensure GitHub repository has vulnerability alerts enabled |
| [CKV_GIT_4](./rules/CKV_GIT_4.md) | HIGH (7.5/10) | Ensure GitHub Actions secrets are encrypted |
| [CKV_GIT_5](./rules/CKV_GIT_5.md) | MEDIUM (5.0/10) | GitHub pull requests should require at least 2 approvals |
| [CKV_GIT_6](./rules/CKV_GIT_6.md) | LOW (2.0/10) | Ensure GitHub branch protection rules requires signed commits |

## GITHUB

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_GITHUB_1](./rules/CKV_GITHUB_1.md) | HIGH (7.5/10) | Ensure GitHub organization security settings require 2FA |
| [CKV_GITHUB_2](./rules/CKV_GITHUB_2.md) | HIGH (7.5/10) | Ensure GitHub organization security settings require SSO |
| [CKV_GITHUB_3](./rules/CKV_GITHUB_3.md) | HIGH (7/10) | Ensure GitHub organization security settings has IP allow list enabled |
| [CKV_GITHUB_4](./rules/CKV_GITHUB_4.md) | LOW (2.0/10) | Ensure GitHub branch protection rules requires signed commits |
| [CKV_GITHUB_5](./rules/CKV_GITHUB_5.md) | MEDIUM (5.5/10) | Ensure GitHub branch protection rules does not allow force pushes |
| [CKV_GITHUB_6](./rules/CKV_GITHUB_6.md) | HIGH (7/10) | Ensure GitHub organization webhooks are using HTTPS |
| [CKV_GITHUB_7](./rules/CKV_GITHUB_7.md) | HIGH (7/10) | Ensure GitHub repository webhooks are using HTTPS |
| [CKV_GITHUB_8](./rules/CKV_GITHUB_8.md) | LOW (3/10) | Ensure GitHub branch protection rules requires linear history |
| [CKV_GITHUB_9](./rules/CKV_GITHUB_9.md) | MEDIUM (4.5/10) | Ensure 2 admins are set for each repository |
| [CKV_GITHUB_10](./rules/CKV_GITHUB_10.md) | LOW (2.0/10) | Ensure branch protection rules are enforced on administrators |
| [CKV_GITHUB_11](./rules/CKV_GITHUB_11.md) | MEDIUM (5.0/10) | Ensure GitHub branch protection dismisses stale review on new commit |
| [CKV_GITHUB_12](./rules/CKV_GITHUB_12.md) | MEDIUM (6/10) | Ensure GitHub branch protection restricts who can dismiss PR reviews |
| [CKV_GITHUB_13](./rules/CKV_GITHUB_13.md) | MEDIUM (5.0/10) | Ensure GitHub branch protection requires CODEOWNER reviews |
| [CKV_GITHUB_14](./rules/CKV_GITHUB_14.md) | MEDIUM (5.5/10) | Ensure all checks have passed before the merge of new code |
| [CKV_GITHUB_15](./rules/CKV_GITHUB_15.md) | LOW (3/10) | Ensure inactive branches are reviewed and removed periodically |
| [CKV_GITHUB_16](./rules/CKV_GITHUB_16.md) | MEDIUM (4.5/10) | Ensure GitHub branch protection requires conversation resolution |
| [CKV_GITHUB_17](./rules/CKV_GITHUB_17.md) | HIGH (7.5/10) | Ensure GitHub branch protection requires push restrictions |
| [CKV_GITHUB_18](./rules/CKV_GITHUB_18.md) | MEDIUM (5/10) | Ensure GitHub branch protection rules does not allow deletions |
| [CKV_GITHUB_19](./rules/CKV_GITHUB_19.md) | HIGH (7.5/10) | Ensure any change to code receives approval of two strongly authenticated users |
| [CKV_GITHUB_20](./rules/CKV_GITHUB_20.md) | LOW (2.0/10) | Ensure open git branches are up to date before they can be merged into codebase |
| [CKV_GITHUB_21](./rules/CKV_GITHUB_21.md) | LOW (2.0/10) | Ensure public repository creation is limited to specific members |
| [CKV_GITHUB_22](./rules/CKV_GITHUB_22.md) | LOW (2.0/10) | Ensure private repository creation is limited to specific members |
| [CKV_GITHUB_23](./rules/CKV_GITHUB_23.md) | LOW (2.0/10) | Ensure internal repository creation is limited to specific members |
| [CKV_GITHUB_26](./rules/CKV_GITHUB_26.md) | HIGH (7/10) | Ensure minimum admins are set for the organization |
| [CKV_GITHUB_27](./rules/CKV_GITHUB_27.md) | LOW (2.0/10) | Ensure strict base permissions are set for repositories |
| [CKV_GITHUB_28](./rules/CKV_GITHUB_28.md) | LOW (2/10) | Ensure an organization's identity is confirmed with a Verified badge |

## GITLAB

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_GITLAB_1](./rules/CKV_GITLAB_1.md) | MEDIUM (5.0/10) | Merge requests should require at least 2 approvals |

## GITLABCI

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_GITLABCI_1](./rules/CKV_GITLABCI_1.md) | HIGH (8/10) | Suspicious use of curl with CI environment variables in script |
| [CKV_GITLABCI_2](./rules/CKV_GITLABCI_2.md) | LOW (2.5/10) | Avoid creating rules that generate double pipelines |
| [CKV_GITLABCI_3](./rules/CKV_GITLABCI_3.md) | LOW (2/10) | Detecting image usages in gitlab workflows |

## GLB

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_GLB_1](./rules/CKV_GLB_1.md) | MEDIUM (5.0/10) | Ensure at least two approving reviews are required to merge a GitLab MR |
| [CKV_GLB_2](./rules/CKV_GLB_2.md) | MEDIUM (5.0/10) | Ensure GitLab branch protection rules does not allow force pushes |
| [CKV_GLB_3](./rules/CKV_GLB_3.md) | MEDIUM (5.0/10) | Ensure GitLab prevent secrets is enabled |
| [CKV_GLB_4](./rules/CKV_GLB_4.md) | LOW (2.0/10) | Ensure GitLab commits are signed |

## IBM

| Rule ID | Severity | Description |
|---|---|---|
| [CKV2_IBM_1](./rules/CKV2_IBM_1.md) | HIGH (7.2/10) | Ensure load balancer for VPC is private (disable public access) |
| [CKV2_IBM_2](./rules/CKV2_IBM_2.md) | HIGH (7.5/10) | Ensure VPC classic access is disabled |
| [CKV2_IBM_3](./rules/CKV2_IBM_3.md) | MEDIUM (5.0/10) | Ensure API key creation is restricted in account settings |
| [CKV2_IBM_4](./rules/CKV2_IBM_4.md) | MEDIUM (5.0/10) | Ensure Multi-Factor Authentication (MFA) is enabled at the account level |
| [CKV2_IBM_5](./rules/CKV2_IBM_5.md) | MEDIUM (5.0/10) | Ensure Service ID creation is restricted in account settings |
| [CKV2_IBM_7](./rules/CKV2_IBM_7.md) | CRITICAL (9/10) | Ensure Kubernetes clusters are accessible by using private endpoint and NOT public endpoint |

## K8S

| Rule ID | Severity | Description |
|---|---|---|
| [CKV2_K8S_1](./rules/CKV2_K8S_1.md) | HIGH (7.5/10) | RoleBinding should not allow privilege escalation to a ServiceAccount or Node on other RoleBinding |
| [CKV_K8S_1](./rules/CKV_K8S_1.md) | MEDIUM (5.0/10) | Do not admit containers wishing to share the host process ID namespace |
| [CKV2_K8S_2](./rules/CKV2_K8S_2.md) | HIGH (7.5/10) | Granting `create` permissions to `nodes/proxy` or `pods/exec` sub resources allows potential privilege escalation |
| [CKV_K8S_2](./rules/CKV_K8S_2.md) | HIGH (7.5/10) | Do not admit privileged containers (PodSecurityPolicy) |
| [CKV2_K8S_3](./rules/CKV2_K8S_3.md) | HIGH (7.5/10) | No ServiceAccount/Node should have `impersonate` permissions for groups/users/service-accounts |
| [CKV_K8S_3](./rules/CKV_K8S_3.md) | MEDIUM (5.0/10) | Do not admit containers wishing to share the host IPC namespace |
| [CKV2_K8S_4](./rules/CKV2_K8S_4.md) | MEDIUM (5.0/10) | ServiceAccounts and nodes that can modify services/status may exploit CVE-2020-8554 for MiTM attacks |
| [CKV_K8S_4](./rules/CKV_K8S_4.md) | MEDIUM (5.0/10) | Do not admit containers wishing to share the host network namespace |
| [CKV2_K8S_5](./rules/CKV2_K8S_5.md) | HIGH (7.5/10) | No ServiceAccount/Node should be able to read all secrets |
| [CKV_K8S_5](./rules/CKV_K8S_5.md) | MEDIUM (5.0/10) | Containers should not run with allowPrivilegeEscalation |
| [CKV2_K8S_6](./rules/CKV2_K8S_6.md) | MEDIUM (5/10) | Minimize the admission of pods which lack an associated NetworkPolicy |
| [CKV_K8S_6](./rules/CKV_K8S_6.md) | MEDIUM (5.0/10) | Do not admit root containers |
| [CKV_K8S_7](./rules/CKV_K8S_7.md) | LOW (2.0/10) | Do not admit containers with the NET_RAW capability |
| [CKV_K8S_8](./rules/CKV_K8S_8.md) | LOW (2.0/10) | Liveness Probe Should be Configured |
| [CKV_K8S_9](./rules/CKV_K8S_9.md) | LOW (2.0/10) | Readiness Probe Should be Configured |
| [CKV_K8S_10](./rules/CKV_K8S_10.md) | LOW (2.0/10) | CPU requests should be set |
| [CKV_K8S_11](./rules/CKV_K8S_11.md) | LOW (2.0/10) | CPU limits should be set |
| [CKV_K8S_12](./rules/CKV_K8S_12.md) | LOW (2.0/10) | Memory requests should be set |
| [CKV_K8S_13](./rules/CKV_K8S_13.md) | LOW (2.0/10) | Memory limits should be set |
| [CKV_K8S_14](./rules/CKV_K8S_14.md) | LOW (2.0/10) | Image Tag should be fixed - not latest or blank |
| [CKV_K8S_15](./rules/CKV_K8S_15.md) | LOW (2.0/10) | Image Pull Policy should be Always |
| [CKV_K8S_16](./rules/CKV_K8S_16.md) | HIGH (7.5/10) | Container should not be privileged |
| [CKV_K8S_17](./rules/CKV_K8S_17.md) | MEDIUM (5.0/10) | Do not admit containers wishing to share the host process ID namespace |
| [CKV_K8S_18](./rules/CKV_K8S_18.md) | MEDIUM (5.0/10) | Do not admit containers wishing to share the host IPC namespace |
| [CKV_K8S_19](./rules/CKV_K8S_19.md) | MEDIUM (5.0/10) | Do not admit containers wishing to share the host network namespace |
| [CKV_K8S_20](./rules/CKV_K8S_20.md) | MEDIUM (5.0/10) | Containers should not run with allowPrivilegeEscalation |
| [CKV_K8S_21](./rules/CKV_K8S_21.md) | LOW (2.0/10) | The default namespace should not be used |
| [CKV_K8S_22](./rules/CKV_K8S_22.md) | LOW (2.0/10) | Use read-only filesystem for containers where possible |
| [CKV_K8S_23](./rules/CKV_K8S_23.md) | MEDIUM (5.0/10) | Minimize the admission of root containers |
| [CKV_K8S_24](./rules/CKV_K8S_24.md) | LOW (2.0/10) | Do not allow containers with added capability (PodSecurityPolicy) |
| [CKV_K8S_25](./rules/CKV_K8S_25.md) | LOW (2.0/10) | Minimize the admission of containers with added capability |
| [CKV_K8S_26](./rules/CKV_K8S_26.md) | LOW (2.0/10) | Do not specify hostPort unless absolutely necessary |
| [CKV_K8S_27](./rules/CKV_K8S_27.md) | MEDIUM (5.0/10) | Do not expose the docker daemon socket to containers |
| [CKV_K8S_28](./rules/CKV_K8S_28.md) | LOW (2.0/10) | Minimize the admission of containers with the NET_RAW capability |
| [CKV_K8S_29](./rules/CKV_K8S_29.md) | LOW (2.0/10) | Apply security context to your pods, deployments and daemon_sets |
| [CKV_K8S_30](./rules/CKV_K8S_30.md) | LOW (2.0/10) | Apply security context to your pods and containers |
| [CKV_K8S_31](./rules/CKV_K8S_31.md) | LOW (2.0/10) | Ensure that the seccomp profile is set to docker/default or runtime/default |
| [CKV_K8S_32](./rules/CKV_K8S_32.md) | LOW (2.0/10) | Ensure default seccomp profile set to docker/default or runtime/default |
| [CKV_K8S_33](./rules/CKV_K8S_33.md) | LOW (2.0/10) | Ensure the Kubernetes dashboard is not deployed |
| [CKV_K8S_34](./rules/CKV_K8S_34.md) | LOW (2.0/10) | Ensure that Tiller (Helm v2) is not deployed |
| [CKV_K8S_35](./rules/CKV_K8S_35.md) | LOW (2.0/10) | Prefer using secrets as files over secrets as environment variables |
| [CKV_K8S_36](./rules/CKV_K8S_36.md) | LOW (2.0/10) | Minimize the admission of containers with capabilities assigned (PodSecurityPolicy) |
| [CKV_K8S_37](./rules/CKV_K8S_37.md) | LOW (2.0/10) | Minimize the admission of containers with capabilities assigned (container securityContext) |
| [CKV_K8S_38](./rules/CKV_K8S_38.md) | LOW (2.0/10) | Ensure that Service Account Tokens are only mounted where necessary |
| [CKV_K8S_39](./rules/CKV_K8S_39.md) | HIGH (7.5/10) | Do not use the CAP_SYS_ADMIN linux capability |
| [CKV_K8S_40](./rules/CKV_K8S_40.md) | LOW (2.0/10) | Containers should run as a high UID to avoid host conflict |
| [CKV_K8S_41](./rules/CKV_K8S_41.md) | LOW (2.0/10) | Ensure that default service accounts are not actively used (ServiceAccount) |
| [CKV_K8S_42](./rules/CKV_K8S_42.md) | LOW (2.0/10) | Ensure that default service accounts are not actively used (RoleBinding/ClusterRoleBinding) |
| [CKV_K8S_43](./rules/CKV_K8S_43.md) | LOW (2.0/10) | Image should use digest |
| [CKV_K8S_44](./rules/CKV_K8S_44.md) | LOW (2.0/10) | Ensure that the Tiller Service (Helm v2) is deleted |
| [CKV_K8S_45](./rules/CKV_K8S_45.md) | HIGH (8/10) | Ensure the Tiller Deployment (Helm V2) is not accessible from within the cluster |
| [CKV_K8S_49](./rules/CKV_K8S_49.md) | MEDIUM (5.0/10) | Minimize wildcard use in Roles and ClusterRoles |
| [CKV_K8S_68](./rules/CKV_K8S_68.md) | LOW (2.0/10) | Ensure that the --anonymous-auth argument is set to false |
| [CKV_K8S_69](./rules/CKV_K8S_69.md) | LOW (2.0/10) | Ensure that the --basic-auth-file argument is not set |
| [CKV_K8S_70](./rules/CKV_K8S_70.md) | LOW (2.0/10) | Ensure that the --token-auth-file argument is not set |
| [CKV_K8S_71](./rules/CKV_K8S_71.md) | HIGH (7.5/10) | Ensure that the --kubelet-https argument is set to true |
| [CKV_K8S_72](./rules/CKV_K8S_72.md) | HIGH (7.5/10) | Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate |
| [CKV_K8S_73](./rules/CKV_K8S_73.md) | HIGH (7.5/10) | Ensure that the --kubelet-certificate-authority argument is set as appropriate |
| [CKV_K8S_74](./rules/CKV_K8S_74.md) | MEDIUM (5.0/10) | Ensure that the --authorization-mode argument is not set to AlwaysAllow |
| [CKV_K8S_75](./rules/CKV_K8S_75.md) | MEDIUM (5.0/10) | Ensure that the --authorization-mode argument includes Node |
| [CKV_K8S_77](./rules/CKV_K8S_77.md) | LOW (2.0/10) | Ensure that the --authorization-mode argument includes RBAC |
| [CKV_K8S_78](./rules/CKV_K8S_78.md) | MEDIUM (5.0/10) | Ensure that the admission control plugin EventRateLimit is set |
| [CKV_K8S_79](./rules/CKV_K8S_79.md) | MEDIUM (5.0/10) | Ensure that the admission control plugin AlwaysAdmit is not set |
| [CKV_K8S_80](./rules/CKV_K8S_80.md) | MEDIUM (5.0/10) | Ensure that the admission control plugin AlwaysPullImages is set |
| [CKV_K8S_81](./rules/CKV_K8S_81.md) | LOW (2.0/10) | Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used |
| [CKV_K8S_82](./rules/CKV_K8S_82.md) | LOW (2.0/10) | Ensure that the admission control plugin ServiceAccount is set |
| [CKV_K8S_83](./rules/CKV_K8S_83.md) | LOW (2.0/10) | Ensure that the admission control plugin NamespaceLifecycle is set |
| [CKV_K8S_84](./rules/CKV_K8S_84.md) | LOW (2.0/10) | Ensure that the admission control plugin PodSecurityPolicy is set |
| [CKV_K8S_85](./rules/CKV_K8S_85.md) | MEDIUM (5.0/10) | Ensure that the admission control plugin NodeRestriction is set |
| [CKV_K8S_86](./rules/CKV_K8S_86.md) | CRITICAL (9.1/10) | Ensure that the --insecure-bind-address argument is not set |
| [CKV_K8S_88](./rules/CKV_K8S_88.md) | CRITICAL (9.1/10) | Ensure that the --insecure-port argument is set to 0 |
| [CKV_K8S_89](./rules/CKV_K8S_89.md) | HIGH (8/10) | Ensure that the --secure-port argument is not set to 0 |
| [CKV_K8S_90](./rules/CKV_K8S_90.md) | LOW (2.0/10) | Ensure that the --profiling argument is set to false |
| [CKV_K8S_91](./rules/CKV_K8S_91.md) | MEDIUM (5.0/10) | Ensure that the --audit-log-path argument is set |
| [CKV_K8S_92](./rules/CKV_K8S_92.md) | LOW (2.0/10) | Ensure that the --audit-log-maxage argument is set to 30 or as appropriate |
| [CKV_K8S_93](./rules/CKV_K8S_93.md) | LOW (2.0/10) | Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate |
| [CKV_K8S_94](./rules/CKV_K8S_94.md) | LOW (2.0/10) | Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate |
| [CKV_K8S_95](./rules/CKV_K8S_95.md) | MEDIUM (5.0/10) | Ensure that the --request-timeout argument is set as appropriate |
| [CKV_K8S_96](./rules/CKV_K8S_96.md) | HIGH (7.5/10) | Ensure that the --service-account-lookup argument is set to true |
| [CKV_K8S_97](./rules/CKV_K8S_97.md) | MEDIUM (5.0/10) | Ensure that the --service-account-key-file argument is set as appropriate |
| [CKV_K8S_99](./rules/CKV_K8S_99.md) | HIGH (7.5/10) | Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate |
| [CKV_K8S_100](./rules/CKV_K8S_100.md) | CRITICAL (9/10) | Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate |
| [CKV_K8S_102](./rules/CKV_K8S_102.md) | HIGH (7.5/10) | Ensure that the --etcd-cafile argument is set as appropriate |
| [CKV_K8S_104](./rules/CKV_K8S_104.md) | HIGH (7.5/10) | Ensure that encryption providers are appropriately configured |
| [CKV_K8S_105](./rules/CKV_K8S_105.md) | HIGH (7.5/10) | Ensure that the API Server only makes use of Strong Cryptographic Ciphers |
| [CKV_K8S_106](./rules/CKV_K8S_106.md) | MEDIUM (5.0/10) | Ensure that the --terminated-pod-gc-threshold argument is set as appropriate |
| [CKV_K8S_107](./rules/CKV_K8S_107.md) | MEDIUM (5.0/10) | Ensure that the --profiling argument is set to false (kube-controller-manager) |
| [CKV_K8S_108](./rules/CKV_K8S_108.md) | HIGH (7.5/10) | Ensure that the --use-service-account-credentials argument is set to true |
| [CKV_K8S_110](./rules/CKV_K8S_110.md) | HIGH (7.5/10) | Ensure that the --service-account-private-key-file argument is set as appropriate |
| [CKV_K8S_111](./rules/CKV_K8S_111.md) | HIGH (7.5/10) | Ensure that the --root-ca-file argument is set as appropriate |
| [CKV_K8S_112](./rules/CKV_K8S_112.md) | MEDIUM (5.0/10) | Ensure that the RotateKubeletServerCertificate argument is set to true |
| [CKV_K8S_113](./rules/CKV_K8S_113.md) | HIGH (7.5/10) | Ensure that the --bind-address argument is set to 127.0.0.1 (kube-controller-manager) |
| [CKV_K8S_114](./rules/CKV_K8S_114.md) | LOW (2.0/10) | Ensure that the --profiling argument is set to false (kube-scheduler) |
| [CKV_K8S_115](./rules/CKV_K8S_115.md) | HIGH (7.5/10) | Ensure that the --bind-address argument is set to 127.0.0.1 (kube-scheduler) |
| [CKV_K8S_116](./rules/CKV_K8S_116.md) | HIGH (7.5/10) | Ensure that the --cert-file and --key-file arguments are set as appropriate |
| [CKV_K8S_117](./rules/CKV_K8S_117.md) | MEDIUM (5.0/10) | Ensure that the --client-cert-auth argument is set to true |
| [CKV_K8S_118](./rules/CKV_K8S_118.md) | HIGH (7.5/10) | Ensure that the --auto-tls argument is not set to true |
| [CKV_K8S_119](./rules/CKV_K8S_119.md) | HIGH (7.5/10) | Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate |
| [CKV_K8S_121](./rules/CKV_K8S_121.md) | HIGH (7.5/10) | Ensure that the --peer-client-cert-auth argument is set to true |
| [CKV_K8S_138](./rules/CKV_K8S_138.md) | MEDIUM (5.0/10) | Ensure that the --anonymous-auth argument is set to false |
| [CKV_K8S_139](./rules/CKV_K8S_139.md) | LOW (2.0/10) | Ensure that the --authorization-mode argument is not set to AlwaysAllow |
| [CKV_K8S_140](./rules/CKV_K8S_140.md) | LOW (2.0/10) | Ensure that the --client-ca-file argument is set as appropriate |
| [CKV_K8S_141](./rules/CKV_K8S_141.md) | HIGH (7.5/10) | Ensure that the --read-only-port argument is set to 0 |
| [CKV_K8S_143](./rules/CKV_K8S_143.md) | LOW (2.0/10) | Ensure that the --streaming-connection-idle-timeout argument is not set to 0 |
| [CKV_K8S_144](./rules/CKV_K8S_144.md) | LOW (2.0/10) | Ensure that the --protect-kernel-defaults argument is set to true |
| [CKV_K8S_145](./rules/CKV_K8S_145.md) | LOW (2.0/10) | Ensure that the --make-iptables-util-chains argument is set to true |
| [CKV_K8S_146](./rules/CKV_K8S_146.md) | LOW (2.0/10) | Ensure that the --hostname-override argument is not set |
| [CKV_K8S_147](./rules/CKV_K8S_147.md) | LOW (2.0/10) | Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture |
| [CKV_K8S_148](./rules/CKV_K8S_148.md) | HIGH (7.5/10) | Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate |
| [CKV_K8S_149](./rules/CKV_K8S_149.md) | HIGH (7.5/10) | Ensure that the --rotate-certificates argument is not set to false |
| [CKV_K8S_151](./rules/CKV_K8S_151.md) | LOW (2.0/10) | Ensure that the Kubelet only makes use of Strong Cryptographic Ciphers |
| [CKV_K8S_152](./rules/CKV_K8S_152.md) | LOW (2.0/10) | Prevent NGINX Ingress annotation snippets which contain LUA code execution (CVE-2021-25742) |
| [CKV_K8S_153](./rules/CKV_K8S_153.md) | LOW (2.0/10) | Prevent All NGINX Ingress annotation snippets (CVE-2021-25742) |
| [CKV_K8S_154](./rules/CKV_K8S_154.md) | LOW (2.0/10) | Prevent NGINX Ingress annotation snippets which contain alias statements (CVE-2021-25742) |
| [CKV_K8S_155](./rules/CKV_K8S_155.md) | HIGH (7.5/10) | Minimize ClusterRoles that grant control over validating or mutating admission webhook configurations |
| [CKV_K8S_156](./rules/CKV_K8S_156.md) | HIGH (7.5/10) | Minimize ClusterRoles that grant permissions to approve CertificateSigningRequests |
| [CKV_K8S_157](./rules/CKV_K8S_157.md) | MEDIUM (5.0/10) | Minimize Roles and ClusterRoles that grant permissions to bind RoleBindings or ClusterRoleBindings |
| [CKV_K8S_158](./rules/CKV_K8S_158.md) | MEDIUM (5.0/10) | Minimize Roles and ClusterRoles that grant permissions to escalate Roles or ClusterRoles |
| [CKV_K8S_159](./rules/CKV_K8S_159.md) | HIGH (7.5/10) | Limit the use of git-sync to prevent code injection |

## LIN

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_LIN_1](./rules/CKV_LIN_1.md) | CRITICAL (9.5/10) | Ensure no hard coded Linode tokens exist in provider |
| [CKV_LIN_2](./rules/CKV_LIN_2.md) | MEDIUM (5/10) | Ensure SSH key set in authorized_keys |
| [CKV_LIN_3](./rules/CKV_LIN_3.md) | LOW (1.5/10) | Ensure email is set |
| [CKV_LIN_4](./rules/CKV_LIN_4.md) | LOW (1.5/10) | Ensure username is set |
| [CKV_LIN_5](./rules/CKV_LIN_5.md) | HIGH (7.5/10) | Ensure Inbound Firewall Policy is not set to ACCEPT |
| [CKV_LIN_6](./rules/CKV_LIN_6.md) | MEDIUM (5/10) | Ensure Outbound Firewall Policy is not set to ACCEPT |

## NCP

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_NCP_1](./rules/CKV_NCP_1.md) | MEDIUM (4/10) | Ensure HTTP HTTPS Target group defines Healthcheck |
| [CKV_NCP_2](./rules/CKV_NCP_2.md) | LOW (2/10) | Ensure every access control groups rule has a description |
| [CKV_NCP_3](./rules/CKV_NCP_3.md) | MEDIUM (5.5/10) | Ensure no security group rules allow outbound traffic to 0.0.0.0/0 |
| [CKV_NCP_4](./rules/CKV_NCP_4.md) | CRITICAL (9/10) | Ensure no access control groups allow inbound from 0.0.0.0:0 to port 22 |
| [CKV_NCP_5](./rules/CKV_NCP_5.md) | CRITICAL (9/10) | Ensure no access control groups allow inbound from 0.0.0.0:0 to port 3389 |
| [CKV_NCP_6](./rules/CKV_NCP_6.md) | HIGH (7/10) | Ensure Server instance is encrypted. |
| [CKV_NCP_7](./rules/CKV_NCP_7.md) | HIGH (7/10) | Ensure Basic Block storage is encrypted. |
| [CKV_NCP_8](./rules/CKV_NCP_8.md) | HIGH (7.5/10) | Ensure no NACL allow inbound from 0.0.0.0:0 to port 20 |
| [CKV_NCP_9](./rules/CKV_NCP_9.md) | HIGH (7.5/10) | Ensure no NACL allow inbound from 0.0.0.0:0 to port 21 |
| [CKV_NCP_10](./rules/CKV_NCP_10.md) | CRITICAL (9.5/10) | Ensure no NACL allow inbound from 0.0.0.0:0 to port 22 |
| [CKV_NCP_11](./rules/CKV_NCP_11.md) | CRITICAL (9.5/10) | Ensure no NACL allow inbound from 0.0.0.0:0 to port 3389 |
| [CKV_NCP_12](./rules/CKV_NCP_12.md) | CRITICAL (9/10) | An inbound Network ACL rule should not allow ALL ports. |
| [CKV_NCP_13](./rules/CKV_NCP_13.md) | HIGH (7.5/10) | Ensure LB Listener uses only secure protocols |
| [CKV_NCP_14](./rules/CKV_NCP_14.md) | HIGH (7.5/10) | Ensure NAS is securely encrypted |
| [CKV_NCP_15](./rules/CKV_NCP_15.md) | HIGH (7/10) | Ensure Load Balancer Target Group is not using HTTP |
| [CKV_NCP_16](./rules/CKV_NCP_16.md) | HIGH (7.5/10) | Ensure Load Balancer isn't exposed to the internet |
| [CKV_NCP_18](./rules/CKV_NCP_18.md) | MEDIUM (4/10) | Ensure that auto Scaling groups that are associated with a load balancer, are using Load Balancing health checks. |
| [CKV_NCP_19](./rules/CKV_NCP_19.md) | CRITICAL (9/10) | Ensure Naver Kubernetes Service public endpoint disabled |
| [CKV_NCP_20](./rules/CKV_NCP_20.md) | LOW (3/10) | Ensure Routing Table associated with Web tier subnet have the default route (0.0.0.0/0) defined to allow connectivity |
| [CKV_NCP_22](./rules/CKV_NCP_22.md) | HIGH (7/10) | Ensure NKS control plane logging enabled for all log types |
| [CKV_NCP_23](./rules/CKV_NCP_23.md) | HIGH (7.5/10) | Ensure Server instance should not have public IP |
| [CKV_NCP_24](./rules/CKV_NCP_24.md) | HIGH (7/10) | Ensure Load Balancer Listener Using HTTPS |
| [CKV_NCP_25](./rules/CKV_NCP_25.md) | MEDIUM (5/10) | Ensure no access control groups allow inbound from 0.0.0.0:0 to port 80 |
| [CKV_NCP_26](./rules/CKV_NCP_26.md) | LOW (3/10) | Ensure Access Control Group has Access Control Group Rule attached |

## OCI

| Rule ID | Severity | Description |
|---|---|---|
| [CKV2_OCI_1](./rules/CKV2_OCI_1.md) | MEDIUM (5.0/10) | Ensure administrator users are not associated with API keys |
| [CKV_OCI_1](./rules/CKV_OCI_1.md) | LOW (2.0/10) | Ensure no hard coded OCI private key in provider |
| [CKV2_OCI_2](./rules/CKV2_OCI_2.md) | CRITICAL (9.5/10) | Ensure NSG does not allow all traffic on RDP port (3389) |
| [CKV_OCI_2](./rules/CKV_OCI_2.md) | LOW (2.0/10) | Ensure OCI Block Storage Block Volume has backup enabled |
| [CKV2_OCI_3](./rules/CKV2_OCI_3.md) | MEDIUM (5/10) | Ensure Kubernetes engine cluster is configured with NSG(s) |
| [CKV_OCI_3](./rules/CKV_OCI_3.md) | LOW (2.0/10) | OCI Block Storage Block Volumes are not encrypted with a Customer Managed Key (CMK) |
| [CKV2_OCI_4](./rules/CKV2_OCI_4.md) | MEDIUM (5.0/10) | Ensure File Storage File System access is restricted to root users |
| [CKV_OCI_4](./rules/CKV_OCI_4.md) | LOW (2.0/10) | Ensure OCI Compute Instance boot volume has in-transit data encryption enabled |
| [CKV2_OCI_5](./rules/CKV2_OCI_5.md) | LOW (2.0/10) | Ensure Kubernetes Engine Cluster boot volume is configured with in-transit data encryption |
| [CKV_OCI_5](./rules/CKV_OCI_5.md) | MEDIUM (5.0/10) | Ensure OCI Compute Instance has Legacy MetaData service endpoint disabled |
| [CKV2_OCI_6](./rules/CKV2_OCI_6.md) | HIGH (7.5/10) | Ensure Kubernetes Engine Cluster pod security policy is enforced |
| [CKV_OCI_6](./rules/CKV_OCI_6.md) | LOW (2.0/10) | Ensure OCI Compute Instance has monitoring enabled |
| [CKV_OCI_7](./rules/CKV_OCI_7.md) | LOW (2.0/10) | Ensure OCI Object Storage bucket can emit object events |
| [CKV_OCI_8](./rules/CKV_OCI_8.md) | LOW (2.0/10) | Ensure OCI Object Storage has versioning enabled |
| [CKV_OCI_9](./rules/CKV_OCI_9.md) | LOW (2.0/10) | Ensure OCI Object Storage is encrypted with Customer Managed Key |
| [CKV_OCI_10](./rules/CKV_OCI_10.md) | HIGH (7.5/10) | Ensure OCI Object Storage is not Public |
| [CKV_OCI_11](./rules/CKV_OCI_11.md) | MEDIUM (5.0/10) | OCI IAM password policy - must contain lower case |
| [CKV_OCI_12](./rules/CKV_OCI_12.md) | MEDIUM (5.0/10) | OCI IAM password policy - must contain Numeric characters |
| [CKV_OCI_13](./rules/CKV_OCI_13.md) | MEDIUM (5.0/10) | OCI IAM password policy - must contain Special characters |
| [CKV_OCI_14](./rules/CKV_OCI_14.md) | MEDIUM (5.0/10) | OCI IAM password policy - must contain Uppercase characters |
| [CKV_OCI_15](./rules/CKV_OCI_15.md) | LOW (2.0/10) | Ensure OCI File System is Encrypted with a customer Managed Key |
| [CKV_OCI_16](./rules/CKV_OCI_16.md) | MEDIUM (5/10) | Ensure VCN has an inbound security list |
| [CKV_OCI_17](./rules/CKV_OCI_17.md) | MEDIUM (4.5/10) | Ensure VCN inbound security lists are stateless |
| [CKV_OCI_18](./rules/CKV_OCI_18.md) | MEDIUM (5.0/10) | OCI IAM password policy for local (non-federated) users has a minimum length of 14 characters |
| [CKV_OCI_19](./rules/CKV_OCI_19.md) | CRITICAL (9.1/10) | Ensure no security list allow ingress from 0.0.0.0:0 to port 22 |
| [CKV_OCI_20](./rules/CKV_OCI_20.md) | CRITICAL (9/10) | Ensure no security list allow ingress from 0.0.0.0:0 to port 3389 |
| [CKV_OCI_21](./rules/CKV_OCI_21.md) | MEDIUM (5.0/10) | Ensure security group has stateless ingress security rules |
| [CKV_OCI_22](./rules/CKV_OCI_22.md) | CRITICAL (9.1/10) | Ensure no security groups rules allow ingress from 0.0.0.0/0 to port 22 |
| [CKV_OCI_23](./rules/CKV_OCI_23.md) | HIGH (7.5/10) | Ensure OCI Data Catalog is configured without overly permissive network access |

## OPENAPI

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_OPENAPI_1](./rules/CKV_OPENAPI_1.md) | HIGH (7.8/10) | Ensure that securityDefinitions is defined and not empty - version 2.0 files |
| [CKV_OPENAPI_2](./rules/CKV_OPENAPI_2.md) | LOW (3/10) | Ensure that if the security scheme is not of type 'oauth2', the array value must be empty - version 2.0 files |
| [CKV_OPENAPI_3](./rules/CKV_OPENAPI_3.md) | HIGH (7.5/10) | Ensure that security schemes don't allow cleartext credentials over unencrypted channel - version 3.x.y files |
| [CKV_OPENAPI_4](./rules/CKV_OPENAPI_4.md) | HIGH (7.5/10) | Ensure that the global security field has rules defined |
| [CKV_OPENAPI_5](./rules/CKV_OPENAPI_5.md) | HIGH (7.5/10) | Ensure that security operations is not empty. |
| [CKV_OPENAPI_6](./rules/CKV_OPENAPI_6.md) | HIGH (7.5/10) | Ensure that security requirement defined in securityDefinitions - version 2.0 files |
| [CKV_OPENAPI_7](./rules/CKV_OPENAPI_7.md) | HIGH (7.5/10) | Ensure that the path scheme does not support unencrypted HTTP connection where all transmissions are open to interception- version 2.0 files |
| [CKV_OPENAPI_8](./rules/CKV_OPENAPI_8.md) | HIGH (7.5/10) | Ensure that security is not using 'password' flow in OAuth2 authentication - version 2.0 files |
| [CKV_OPENAPI_9](./rules/CKV_OPENAPI_9.md) | MEDIUM (5.0/10) | Ensure that security scopes of operations are defined in securityDefinitions - version 2.0 files |
| [CKV_OPENAPI_10](./rules/CKV_OPENAPI_10.md) | HIGH (7.5/10) | Ensure that operation object does not use 'password' flow in OAuth2 authentication - version 2.0 files |
| [CKV_OPENAPI_11](./rules/CKV_OPENAPI_11.md) | HIGH (7.5/10) | Ensure that operation object does not use 'password' flow in OAuth2 authentication - version 2.0 files |
| [CKV_OPENAPI_12](./rules/CKV_OPENAPI_12.md) | MEDIUM (5.0/10) | Ensure no security definition is using implicit flow on OAuth2, which is deprecated - version 2.0 files |
| [CKV_OPENAPI_13](./rules/CKV_OPENAPI_13.md) | HIGH (7.5/10) | Ensure security definitions do not use basic auth - version 2.0 files |
| [CKV_OPENAPI_14](./rules/CKV_OPENAPI_14.md) | MEDIUM (5.0/10) | Ensure that operation objects do not use 'implicit' flow, which is deprecated - version 2.0 files |
| [CKV_OPENAPI_15](./rules/CKV_OPENAPI_15.md) | HIGH (7.5/10) | Ensure that operation objects do not use basic auth - version 2.0 files |
| [CKV_OPENAPI_16](./rules/CKV_OPENAPI_16.md) | LOW (2.0/10) | Ensure that operation objects have 'produces' field defined for GET operations - version 2.0 files |
| [CKV_OPENAPI_17](./rules/CKV_OPENAPI_17.md) | MEDIUM (5.0/10) | Ensure that operation objects have 'consumes' field defined for PUT, POST and PATCH operations - version 2.0 files |
| [CKV_OPENAPI_18](./rules/CKV_OPENAPI_18.md) | HIGH (7.5/10) | Ensure that global schemes use 'https' protocol instead of 'http'- version 2.0 files |
| [CKV_OPENAPI_19](./rules/CKV_OPENAPI_19.md) | MEDIUM (5.0/10) | Ensure that global security scope is defined in securityDefinitions - version 2.0 files |
| [CKV_OPENAPI_20](./rules/CKV_OPENAPI_20.md) | HIGH (8/10) | Ensure that API keys are not sent over cleartext |
| [CKV_OPENAPI_21](./rules/CKV_OPENAPI_21.md) | MEDIUM (5.0/10) | Ensure that arrays have a maximum number of items |

## OPENSTACK

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_OPENSTACK_1](./rules/CKV_OPENSTACK_1.md) | LOW (2.0/10) | Ensure no hard coded OpenStack password, token, or application_credential_secret exists in provider |
| [CKV_OPENSTACK_2](./rules/CKV_OPENSTACK_2.md) | CRITICAL (9.1/10) | Ensure no security groups allow ingress from 0.0.0.0:0 to port 22 (tcp / udp) |
| [CKV_OPENSTACK_3](./rules/CKV_OPENSTACK_3.md) | CRITICAL (9.1/10) | Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389 (tcp / udp) |
| [CKV_OPENSTACK_4](./rules/CKV_OPENSTACK_4.md) | LOW (2.0/10) | Ensure that instance does not use basic credentials |
| [CKV_OPENSTACK_5](./rules/CKV_OPENSTACK_5.md) | LOW (2.0/10) | Ensure firewall rule set a destination IP |

## PAN

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_PAN_1](./rules/CKV_PAN_1.md) | CRITICAL (9.5/10) | Ensure no hard coded PAN-OS credentials exist in provider |
| [CKV_PAN_2](./rules/CKV_PAN_2.md) | MEDIUM (5.0/10) | Ensure plain-text management HTTP is not enabled for an Interface Management Profile |
| [CKV_PAN_3](./rules/CKV_PAN_3.md) | MEDIUM (5.0/10) | Ensure plain-text management Telnet is not enabled for an Interface Management Profile |
| [CKV_PAN_4](./rules/CKV_PAN_4.md) | MEDIUM (5.0/10) | Ensure DSRI is not enabled within security policies |
| [CKV_PAN_5](./rules/CKV_PAN_5.md) | MEDIUM (5.0/10) | Ensure security rules do not have 'applications' set to 'any' |
| [CKV_PAN_6](./rules/CKV_PAN_6.md) | LOW (2.0/10) | Ensure security rules do not have 'services' set to 'any' |
| [CKV_PAN_7](./rules/CKV_PAN_7.md) | LOW (2.0/10) | Ensure security rules do not have 'source_addresses' and 'destination_addresses' both containing values of 'any' |
| [CKV_PAN_8](./rules/CKV_PAN_8.md) | LOW (2.0/10) | Ensure description is populated within security policies |
| [CKV_PAN_9](./rules/CKV_PAN_9.md) | LOW (2.0/10) | Ensure a Log Forwarding Profile is selected for each security policy rule |
| [CKV_PAN_10](./rules/CKV_PAN_10.md) | LOW (2.0/10) | Ensure logging at session end is enabled within security policies |
| [CKV_PAN_11](./rules/CKV_PAN_11.md) | HIGH (7.5/10) | Ensure IPsec profiles do not specify use of insecure encryption algorithms |
| [CKV_PAN_12](./rules/CKV_PAN_12.md) | MEDIUM (5.0/10) | Ensure IPsec profiles do not specify use of insecure authentication algorithms |
| [CKV_PAN_13](./rules/CKV_PAN_13.md) | MEDIUM (5.0/10) | Ensure IPsec profiles do not specify use of insecure protocols |
| [CKV_PAN_14](./rules/CKV_PAN_14.md) | LOW (2.0/10) | Ensure a Zone Protection Profile is defined within Security Zones |
| [CKV_PAN_15](./rules/CKV_PAN_15.md) | LOW (2.0/10) | Ensure an Include ACL is defined for a Zone when User-ID is enabled |
| [CKV_PAN_16](./rules/CKV_PAN_16.md) | LOW (2.0/10) | Ensure logging at session start is disabled within security policies except for troubleshooting and long lived GRE tunnels |
| [CKV_PAN_17](./rules/CKV_PAN_17.md) | MEDIUM (5.0/10) | Ensure security rules do not have 'source_zone' and 'destination_zone' both containing values of 'any' |

## SECRET

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_SECRET_1](./rules/CKV_SECRET_1.md) | MEDIUM (5.0/10) | Artifactory Credentials |
| [CKV_SECRET_2](./rules/CKV_SECRET_2.md) | HIGH (7.5/10) | AWS Access Key |
| [CKV_SECRET_3](./rules/CKV_SECRET_3.md) | HIGH (7.5/10) | Azure Storage Account access key |
| [CKV_SECRET_4](./rules/CKV_SECRET_4.md) | MEDIUM (5.0/10) | Basic Auth Credentials |
| [CKV_SECRET_5](./rules/CKV_SECRET_5.md) | LOW (2.0/10) | Cloudant Credentials |
| [CKV_SECRET_6](./rules/CKV_SECRET_6.md) | LOW (2.0/10) | Base64 High Entropy String |
| [CKV_SECRET_7](./rules/CKV_SECRET_7.md) | HIGH (7.5/10) | IBM Cloud IAM Key |
| [CKV_SECRET_8](./rules/CKV_SECRET_8.md) | LOW (2.0/10) | IBM COS HMAC Credentials |
| [CKV_SECRET_9](./rules/CKV_SECRET_9.md) | LOW (2.0/10) | JSON Web Token |
| [CKV_SECRET_11](./rules/CKV_SECRET_11.md) | LOW (2.0/10) | Mailchimp Access Key |
| [CKV_SECRET_12](./rules/CKV_SECRET_12.md) | LOW (2.0/10) | NPM tokens |
| [CKV_SECRET_13](./rules/CKV_SECRET_13.md) | MEDIUM (5.0/10) | Private Key |
| [CKV_SECRET_14](./rules/CKV_SECRET_14.md) | MEDIUM (5.0/10) | Slack Token |
| [CKV_SECRET_15](./rules/CKV_SECRET_15.md) | LOW (2.0/10) | SoftLayer Credentials |
| [CKV_SECRET_16](./rules/CKV_SECRET_16.md) | LOW (2.0/10) | Square OAuth Secret |
| [CKV_SECRET_17](./rules/CKV_SECRET_17.md) | MEDIUM (5.0/10) | Stripe Access Key |
| [CKV_SECRET_18](./rules/CKV_SECRET_18.md) | LOW (2.0/10) | Twilio API Key |
| [CKV_SECRET_19](./rules/CKV_SECRET_19.md) | LOW (2.0/10) | Hex High Entropy String |

## TC

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_TC_1](./rules/CKV_TC_1.md) | HIGH (7/10) | Ensure Tencent Cloud CBS is encrypted |
| [CKV_TC_2](./rules/CKV_TC_2.md) | HIGH (7.5/10) | Ensure Tencent Cloud CVM instance does not allocate a public IP |
| [CKV_TC_3](./rules/CKV_TC_3.md) | MEDIUM (4.5/10) | Ensure Tencent Cloud CVM monitor service is enabled |
| [CKV_TC_4](./rules/CKV_TC_4.md) | MEDIUM (6/10) | Ensure Tencent Cloud CVM instances do not use the default security group |
| [CKV_TC_5](./rules/CKV_TC_5.md) | MEDIUM (4.5/10) | Ensure Tencent Cloud CVM instances do not use the default VPC |
| [CKV_TC_6](./rules/CKV_TC_6.md) | MEDIUM (5/10) | Ensure Tencent Cloud TKE clusters enable log agent |
| [CKV_TC_7](./rules/CKV_TC_7.md) | CRITICAL (9/10) | Ensure Tencent Cloud TKE cluster is not assigned a public IP address |
| [CKV_TC_8](./rules/CKV_TC_8.md) | CRITICAL (8.5/10) | Ensure Tencent Cloud VPC security group rules do not accept all traffic |
| [CKV_TC_9](./rules/CKV_TC_9.md) | CRITICAL (9.1/10) | Ensure Tencent Cloud mysql instances do not enable access from public networks |
| [CKV_TC_10](./rules/CKV_TC_10.md) | LOW (3/10) | Ensure Tencent Cloud MySQL instances intranet ports are not set to the default 3306 |
| [CKV_TC_11](./rules/CKV_TC_11.md) | MEDIUM (4.5/10) | Ensure Tencent Cloud CLB has a logging ID and topic |
| [CKV_TC_12](./rules/CKV_TC_12.md) | HIGH (7.5/10) | Ensure Tencent Cloud CLBs use modern, encrypted protocols |
| [CKV_TC_13](./rules/CKV_TC_13.md) | CRITICAL (8.5/10) | Ensure Tencent Cloud CVM user data does not contain sensitive information |
| [CKV_TC_14](./rules/CKV_TC_14.md) | MEDIUM (5/10) | Ensure Tencent Cloud VPC flow logs are enabled |

## TF

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_TF_1](./rules/CKV_TF_1.md) | MEDIUM (5.0/10) | Ensure Terraform module sources use a commit hash |
| [CKV_TF_2](./rules/CKV_TF_2.md) | HIGH (7.5/10) | Ensure Terraform module sources use a tag with a version number |

## YC

| Rule ID | Severity | Description |
|---|---|---|
| [CKV_YC_1](./rules/CKV_YC_1.md) | HIGH (7.8/10) | Ensure security group is assigned to database cluster. |
| [CKV_YC_2](./rules/CKV_YC_2.md) | HIGH (7.5/10) | Ensure compute instance does not have public IP. |
| [CKV_YC_3](./rules/CKV_YC_3.md) | HIGH (7.5/10) | Ensure storage bucket is encrypted. |
| [CKV_YC_4](./rules/CKV_YC_4.md) | HIGH (8/10) | Ensure compute instance does not have serial console enabled. |
| [CKV_YC_5](./rules/CKV_YC_5.md) | CRITICAL (9/10) | Ensure Kubernetes cluster does not have public IP address. |
| [CKV_YC_6](./rules/CKV_YC_6.md) | HIGH (7/10) | Ensure Kubernetes cluster node group does not have public IP addresses. |
| [CKV_YC_7](./rules/CKV_YC_7.md) | MEDIUM (5/10) | Ensure Kubernetes cluster auto-upgrade is enabled. |
| [CKV_YC_8](./rules/CKV_YC_8.md) | MEDIUM (5/10) | Ensure Kubernetes node group auto-upgrade is enabled. |
| [CKV_YC_9](./rules/CKV_YC_9.md) | MEDIUM (4.5/10) | Ensure KMS symmetric key is rotated. |
| [CKV_YC_10](./rules/CKV_YC_10.md) | HIGH (7.4/10) | Ensure etcd database is encrypted with KMS key. |
| [CKV_YC_11](./rules/CKV_YC_11.md) | HIGH (7.3/10) | Ensure security group is assigned to network interface. |
| [CKV_YC_12](./rules/CKV_YC_12.md) | CRITICAL (9/10) | Ensure public IP is not assigned to database cluster. |
| [CKV_YC_13](./rules/CKV_YC_13.md) | CRITICAL (9.2/10) | Ensure cloud member does not have elevated access. |
| [CKV_YC_14](./rules/CKV_YC_14.md) | HIGH (7.6/10) | Ensure security group is assigned to Kubernetes cluster. |
| [CKV_YC_15](./rules/CKV_YC_15.md) | HIGH (7.2/10) | Ensure security group is assigned to Kubernetes node group. |
| [CKV_YC_16](./rules/CKV_YC_16.md) | MEDIUM (5.8/10) | Ensure network policy is assigned to Kubernetes cluster. |
| [CKV_YC_17](./rules/CKV_YC_17.md) | CRITICAL (9.3/10) | Ensure storage bucket does not have public access permissions. |
| [CKV_YC_18](./rules/CKV_YC_18.md) | HIGH (7.7/10) | Ensure compute instance group does not have public IP. |
| [CKV_YC_19](./rules/CKV_YC_19.md) | CRITICAL (9.4/10) | Ensure security group does not contain allow-all rules. |
| [CKV_YC_20](./rules/CKV_YC_20.md) | CRITICAL (9.4/10) | Ensure security group rule is not allow-all. |
| [CKV_YC_21](./rules/CKV_YC_21.md) | CRITICAL (9.2/10) | Ensure organization member does not have elevated access. |
| [CKV_YC_22](./rules/CKV_YC_22.md) | HIGH (7.6/10) | Ensure compute instance group has security group assigned. |
| [CKV_YC_23](./rules/CKV_YC_23.md) | HIGH (7.5/10) | Ensure folder member does not have elevated access. |
| [CKV_YC_24](./rules/CKV_YC_24.md) | MEDIUM (5.5/10) | Ensure passport account is not used for assignment. Use service accounts and federated accounts where possible. |

