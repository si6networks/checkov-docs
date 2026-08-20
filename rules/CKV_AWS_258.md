# CKV_AWS_258: Ensure that Lambda function URLs AuthType is not None

## Severity
**MEDIUM** (score: 5.0/10)

Setting a Lambda function URL's AuthType to NONE makes the function invocable by anyone on the internet with no authentication, directly exposing whatever the function's execution role and code can reach.

## Summary
This check ensures that a Lambda function URL's authorization type is not set to `NONE`, so that invocations require IAM authentication rather than being open to unauthenticated callers.

## Applicability
- **Frameworks:** CloudFormation, Terraform
- **Resource types:**
  - CloudFormation: `AWS::Lambda::Url`
  - Terraform: `aws_lambda_function_url`

## Why it matters
Lambda function URLs are a dedicated HTTPS endpoint for invoking a Lambda function directly, without API Gateway. Setting `AuthType`/`authorization_type` to `NONE` makes that endpoint **publicly invocable by anyone on the internet with no authentication whatsoever** — not even an API key. This is one of the easiest ways to accidentally expose a backend function (and whatever it does — write to a database, call other AWS APIs using its execution role, process user input) to arbitrary unauthenticated traffic, enabling abuse ranging from denial-of-wallet attacks (racking up invocation/compute charges) to direct exploitation of any injection or logic vulnerability in the function code, to using the function as a pivot to whatever its IAM execution role can reach. `NONE` should only ever be a deliberate, reviewed choice for an intentionally public endpoint (e.g., a public webhook receiver with its own application-layer validation) — never the default.

## How Checkov evaluates this
Both implementations use a `BaseResourceNegativeValueCheck` (a "value must not be one of these forbidden values" check):

- **Terraform:** inspects `authorization_type`; forbidden value is `"NONE"`.
- **CloudFormation:** inspects `Properties/AuthType`; forbidden value is `"NONE"`.

- **PASS**: the auth type is `AWS_IAM` (or any value other than `NONE`).
- **FAIL**: the auth type is explicitly `NONE`.

## Non-compliant example
```hcl
resource "aws_lambda_function_url" "example" {
  function_name      = aws_lambda_function.example.function_name
  authorization_type = "NONE"   # publicly invocable, no authentication
}
```

```yaml
# CloudFormation
Resources:
  MyFunctionUrl:
    Type: AWS::Lambda::Url
    Properties:
      TargetFunctionArn: !GetAtt MyFunction.Arn
      AuthType: NONE
```

## Remediated example
```hcl
resource "aws_lambda_function_url" "example" {
  function_name      = aws_lambda_function.example.function_name
  authorization_type = "AWS_IAM"   # <-- requires SigV4-signed, authorized requests
}
```

```yaml
# CloudFormation
Resources:
  MyFunctionUrl:
    Type: AWS::Lambda::Url
    Properties:
      TargetFunctionArn: !GetAtt MyFunction.Arn
      AuthType: AWS_IAM
```

## Remediation steps
1. Change `authorization_type`/`AuthType` from `NONE` to `AWS_IAM`.
2. Grant the specific callers (IAM users/roles, or another AWS account) `lambda:InvokeFunctionUrl` permission via a resource-based policy (`aws_lambda_permission` with `function_url_auth_type = "AWS_IAM"` in Terraform).
3. Update any client code to sign requests with SigV4 (e.g., using the AWS SDK's request signer) since plain unauthenticated HTTPS calls will now be rejected with 403.
4. If the endpoint genuinely must be public (e.g., a webhook), keep `NONE` only as an explicit, reviewed exception, and compensate with strong application-layer request validation (e.g., verifying a webhook signature header), throttling/reserved concurrency to cap cost/blast radius, and WAF in front of it if fronted by CloudFront/API Gateway.
5. Audit existing function URLs across the account for `NONE` auth type as part of a broader review, since this is a common accidental-exposure pattern.

## References
- [Checkov Terraform check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/LambdaFunctionURLAuth.py)
- [Checkov CloudFormation check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/LambdaFunctionURLAuth.py)
- [AWS: Lambda function URLs](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
