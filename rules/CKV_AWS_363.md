# CKV_AWS_363: Ensure Lambda Runtime is not deprecated

## Severity
**MEDIUM** (score: 5.0/10)

Running on a deprecated, unpatched Lambda runtime increases exposure to known unremediated CVEs in the language runtime or OS libraries, but successful exploitation still depends on a specific vulnerability being present and reachable, making this a real but conditional risk rather than a direct one.

## Summary
This check ensures that Lambda functions do not specify a `runtime` value that AWS has deprecated (no longer receives security patches and is scheduled for, or already subject to, blocked updates/creates).

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** CloudFormation, Terraform
- **Check type:** resource check
- **Entities:** `AWS::Lambda::Function`, `AWS::Serverless::Function` (property `Runtime`), `aws_lambda_function` (attribute `runtime`)

## Why it matters
AWS Lambda runtimes bundle a specific language interpreter/SDK version and OS-level dependencies. When AWS deprecates a runtime, it stops shipping security patches for that runtime's OS packages and language runtime, and eventually blocks both new function creation and (later) updates/invocations of functions still using it. Running on a deprecated runtime means your function executes on an unpatched, unsupported execution environment — increasing exposure to known CVEs in the language runtime or its OS libraries with no vendor remediation path. This is a common transitive-risk source in Lambda-heavy environments: a function that hasn't been touched in years may quietly run on End-of-Support Node.js/Python/Ruby/.NET versions.

## How Checkov evaluates this
This is a negative-value check (`BaseResourceNegativeValueCheck`) against the `runtime` (`Properties/Runtime` in CloudFormation) field. It **FAILS** if the value is present in a hardcoded deny-list of deprecated runtimes maintained in the check source (e.g. `python2.7`, `python3.6`, `python3.7`, `nodejs4.3`, `nodejs6.10`, `nodejs8.10`, `nodejs10.x`, `nodejs12.x`, `nodejs14.x`, `nodejs16.x`, `ruby2.5`, `ruby2.7`, `dotnetcore1.0`/`2.0`/`2.1`/`3.1`, `dotnet5.0`/`6`/`7`, `java8`, `go1.x`, `provided`, and legacy `nodejs`/`nodejs4.3-edge`). Any runtime not on this list **PASSES**. Note the list is periodically updated by the Checkov maintainers as AWS deprecates additional runtimes (comments in the source show planned future additions like `nodejs18.x` and `provided.al2` on specific future dates) — always confirm against your Checkov version's current list and AWS's live deprecation schedule, since this list can lag or precede actual AWS enforcement dates.

## Non-compliant example
```hcl
resource "aws_lambda_function" "legacy_handler" {
  function_name = "legacy-handler"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "nodejs12.x"
  filename      = "function.zip"
}
```

## Remediated example
```hcl
resource "aws_lambda_function" "legacy_handler" {
  function_name = "legacy-handler"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "function.zip"
}
```

## Remediation steps
1. Identify the current supported runtimes for your language at the AWS Lambda runtimes documentation and pick the latest supported major version.
2. Update the `runtime` value and verify your handler code/dependencies are compatible with the new runtime's language version (e.g. Node.js 12 → 20 may require dependency and syntax updates).
3. Test thoroughly in a non-production environment — a runtime bump can be a breaking change depending on SDK/library version pinning.
4. Set up recurring monitoring (e.g. AWS Health notifications, Checkov in CI) since AWS deprecates runtimes on a rolling schedule; a runtime valid today may become deprecated later.
5. For legacy workloads that can't be easily upgraded, consider migrating to a container-image-based Lambda where you control the base image and patch cadence directly.

## References
- Checkov check source (Terraform): https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/DeprecatedLambdaRuntime.py
- Checkov check source (CloudFormation): https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/DeprecatedLambdaRuntime.py
- AWS docs: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
