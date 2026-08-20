# CKV_AWS_384: Ensure no hard-coded secrets exist in Parameter Store values

## Severity
**MEDIUM** (score: 5.0/10)

A hard-coded secret or API key value baked into an SSM Parameter Store resource in a CloudFormation template is a plaintext exposed credential, retrievable long after deployment by anyone with template or stack read access.

## Summary
This check flags AWS Systems Manager Parameter Store (`AWS::SSM::Parameter`) resources whose name suggests it holds a secret/API key and whose static `Value` contains what looks like a real, hard-coded credential rather than a dynamic reference.

## Applicability
- **IaC framework:** CloudFormation
- **Resource type:** `AWS::SSM::Parameter`

## Why it matters
Parameter Store is commonly used to store configuration values, and — despite AWS Secrets Manager being the more purpose-built service for secrets — many teams also store credentials in plain `String` type SSM parameters. When a hard-coded secret value is committed directly into a CloudFormation template:

- The secret is exposed to anyone with read access to the source repository, CI/CD logs, or CloudFormation stack template history (`aws cloudformation get-template` can retrieve it long after deployment).
- It cannot be rotated without a code change and redeploy, and there is no built-in versioning/auditing tied to secret access the way Secrets Manager or SecureString-with-KMS parameters provide.
- Hard-coded secrets in IaC are a leading cause of credential leaks in public and private repositories, since templates are often shared, forked, or archived without anyone scrubbing embedded values.

## How Checkov evaluates this
The check only examines parameters whose `Properties.Name` matches (case-insensitively) the pattern `.*secret.*` or `.*api_?key.*` — i.e., names suggesting secret/API-key content. For matching parameters:

1. If `Properties.Value` is a dict (an unresolved CloudFormation intrinsic function like `!Ref`/`!Sub` object form), it **PASSES** — that's treated as a dynamic reference, not a literal secret.
2. If the value contains an unresolved `${...}` template placeholder, it also **PASSES**.
3. If either the parameter `Name` or `Value` contains the word "test" or "example" (case-insensitive), it **PASSES** — treated as placeholder/test data.
4. Otherwise, it runs the value through Checkov's secret-detection heuristics (`get_secrets_from_string`, checking AWS-key patterns, generic high-entropy secrets, and password-like patterns). If any of these detectors match, the check **FAILS**.
5. Parameters whose name doesn't match the secret/API-key naming pattern at all are not evaluated this way and simply **PASS**.

## Non-compliant example
```yaml
Resources:
  MyApiKeyParam:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /myapp/api_key
      Type: String
      Value: "AKIAIOSFODNN7EXAMPLE1234567890abcdEFGh"
```

## Remediated example
```yaml
Resources:
  MyApiKeyParam:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /myapp/api_key
      Type: SecureString
      Value: !Sub '{{resolve:secretsmanager:${ApiKeySecret}:SecretString:api_key}}'
```

## Remediation steps
1. Never embed literal, live secret values directly in a CloudFormation template's `Value` property.
2. Store the actual secret in AWS Secrets Manager (or a `SecureString` SSM parameter populated out-of-band, e.g., via CLI/console or a separate secure pipeline step) and reference it in the template using the `{{resolve:secretsmanager:...}}` or `{{resolve:ssm-secure:...}}` dynamic reference syntax, or via a `!Sub`/`!Ref` to a parameter supplied at deploy time.
3. If the template must define the parameter's value inline for legitimate test/example purposes, name it clearly with "test" or "example" so the intent is unambiguous (and so this check's built-in exception applies) — but never do this for real credentials.
4. Rotate any credential that was ever committed in plaintext to version control, since git history retains it even after a later fix.
5. This is a template-content fix — no infrastructure downtime — but rotating the underlying secret will require updating any consumer that reads the old value.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/cloudformation/checks/resource/aws/ParameterStoreCredentials.py)
- [AWS Systems Manager Parameter Store documentation](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)
