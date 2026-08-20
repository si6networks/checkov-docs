# CKV2_AWS_75: Ensure no open CORS policy

## Severity
**MEDIUM** (score: 5.0/10)

A wildcard CORS policy lets any origin make authenticated cross-origin requests, enabling credential theft and data exfiltration from browser-based clients.

## Summary
This check ensures that a Lambda Function URL's Cross-Origin Resource Sharing (CORS) configuration does not allow requests from any origin (`*`) combined with any HTTP method (`*`).

## Applicability
**Checkov framework(s):** `cloudformation`, `terraform`

- **IaC frameworks:** Terraform and CloudFormation (implemented as graph-based checks that trace the connection between a Lambda function and its Function URL resource).
- **Resource types:**
  - Terraform: `aws_lambda_function` connected to `aws_lambda_function_url`.
  - CloudFormation: `AWS::Lambda::Function` connected to `AWS::Lambda::Url`.

## Why it matters
AWS Lambda Function URLs are directly invokable HTTPS endpoints. When their CORS configuration allows `AllowOrigins: ["*"]` together with `AllowMethods: ["*"]`, any website in a victim's browser can make authenticated (if `AllowCredentials` were also mishandled) or unauthenticated cross-origin requests to the function and read the response client-side via JavaScript `fetch`/`XHR`. This enables cross-site request forgery-style abuse, data exfiltration from responses that were only meant to be consumed by your own front-end origin, and makes the endpoint trivially scrapeable/abusable by any third-party site embedding a script that calls it. Wildcard CORS defeats the entire purpose of the same-origin policy that browsers otherwise enforce, effectively making the API "public" to any web page regardless of who authored it.

## How Checkov evaluates this
This is a graph check (`LambdaOpenCorsPolicy.json`) evaluated for both Terraform and CloudFormation. Logic (Terraform variant):
1. Filter to `aws_lambda_function` resources.
2. If the function has **no** connected `aws_lambda_function_url` resource, it passes trivially (no Function URL, no CORS surface to worry about).
3. If a Function URL **is** connected, the check requires that at least one of the following conditions on the Function URL's `cors` block does **not** contain a wildcard:
   - `cors.allow_origins` does not contain `"*"`, **or**
   - `cors.allow_methods` does not contain `"*"`.

So it only fails when the Function URL's CORS config allows both `*` origins **and** `*` methods simultaneously (open on both axes). The CloudFormation version checks the equivalent `Cors.AllowOrigins` / `Cors.AllowMethods` properties on `AWS::Lambda::Url`.

## Non-compliant example
```hcl
resource "aws_lambda_function" "api" {
  function_name = "public-api"
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  role          = aws_iam_role.lambda_exec.arn
  filename      = "lambda.zip"
}

resource "aws_lambda_function_url" "api_url" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "NONE"

  cors {
    allow_origins = ["*"]
    allow_methods = ["*"]
  }
}
```

## Remediated example
```hcl
resource "aws_lambda_function" "api" {
  function_name = "public-api"
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  role          = aws_iam_role.lambda_exec.arn
  filename      = "lambda.zip"
}

resource "aws_lambda_function_url" "api_url" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "AWS_IAM"

  cors {
    allow_origins = ["https://app.example.com"]   # explicit origin, not "*"
    allow_methods = ["GET", "POST"]                # explicit methods, not "*"
  }
}
```

## Remediation steps
1. Identify every `aws_lambda_function_url` (or `AWS::Lambda::Url`) resource and inspect its `cors` block.
2. Replace `allow_origins = ["*"]` with an explicit allow-list of the exact origins that legitimately need to call this endpoint (scheme + host, e.g. `https://app.example.com`).
3. Replace `allow_methods = ["*"]` with only the HTTP methods the endpoint actually needs (`GET`, `POST`, etc.).
4. If the function must genuinely be public and stateless with no cookies/credentials involved, wildcard origin alone (without wildcard methods, or vice versa) will still pass this specific check — but consider whether a wildcard is really required at all; prefer an explicit list.
5. Never combine `allow_origins = ["*"]` with `allow_credentials = true` — browsers reject this combination for good reason, and permissive CORS plus credentials is a critical vulnerability pattern.
6. Re-apply; changing `cors` on `aws_lambda_function_url` is an in-place update, no replacement needed.

## References
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/graph_checks/aws/LambdaOpenCorsPolicy.json)
- [Checkov check source (CloudFormation)](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/graph_checks/LambdaOpenCorsPolicy.json)
- [AWS: Cross-origin resource sharing (CORS) for Lambda function URLs](https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html#urls-cors)
