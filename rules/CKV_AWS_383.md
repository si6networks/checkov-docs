# CKV_AWS_383: Ensure AWS Bedrock agent is associated with Bedrock guardrails

## Severity
**LOW** (score: 2.0/10)

A Bedrock agent without an associated guardrail configuration lacks automated controls against harmful, biased, or prompt-injected content, raising the risk of unsafe or manipulated model outputs reaching users.

## Summary
This check ensures every Amazon Bedrock agent has a guardrail configuration associated with it, so the agent's inputs/outputs are filtered by Bedrock Guardrails rather than running unconstrained.

## Applicability
- **IaC framework:** Terraform
- **Resource type:** `aws_bedrockagent_agent`

## Why it matters
Bedrock Guardrails provide content filtering, denied-topic enforcement, PII redaction, and prompt-injection/jailbreak mitigation for generative-AI agent interactions. Without an associated guardrail:

- The agent can be manipulated via prompt injection to leak sensitive information, bypass intended business rules, or generate harmful/off-brand content, since there is no independent safety layer between the underlying foundation model and the end user or downstream system.
- Personally identifiable information (PII) or other sensitive data returned by the agent (e.g., pulled from a knowledge base or action-group tool call) is not automatically redacted before reaching the caller.
- Malicious or adversarial inputs (jailbreak attempts) have no dedicated defense beyond whatever is baked into the base model, which is materially weaker than a dedicated, configurable guardrail policy.

For agents that take actions (via action groups) or have access to internal knowledge bases, an unguarded agent significantly raises the blast radius of a successful prompt-injection attack.

## How Checkov evaluates this
This is a `BaseResourceValueCheck` that inspects the attribute path:

```
guardrail_configuration/[0]/guardrail_identifier
```

The expected value is `ANY_VALUE`, meaning the check **PASSES** as soon as `guardrail_identifier` is set to anything non-empty (i.e., some guardrail is associated) — Checkov does not validate which specific guardrail or its policy content, only that the association exists. If `guardrail_configuration` or `guardrail_identifier` is absent, the check **FAILS**.

## Non-compliant example
```hcl
resource "aws_bedrockagent_agent" "example" {
  agent_name              = "example-agent"
  agent_resource_role_arn = aws_iam_role.bedrock_agent.arn
  foundation_model        = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction             = "You are a helpful customer support agent."
}
```

## Remediated example
```hcl
resource "aws_bedrock_guardrail" "example" {
  name                      = "example-guardrail"
  blocked_input_messaging   = "This request cannot be processed."
  blocked_outputs_messaging = "This response was blocked by content policy."

  content_policy_config {
    filters_config {
      type            = "HATE"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
  }
}

resource "aws_bedrockagent_agent" "example" {
  agent_name              = "example-agent"
  agent_resource_role_arn = aws_iam_role.bedrock_agent.arn
  foundation_model        = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction             = "You are a helpful customer support agent."

  guardrail_configuration {
    guardrail_identifier = aws_bedrock_guardrail.example.guardrail_id
    guardrail_version    = aws_bedrock_guardrail.example.version
  }
}
```

## Remediation steps
1. Create an `aws_bedrock_guardrail` resource defining the content filters, denied topics, PII redaction, and word filters relevant to your agent's use case.
2. Add a `guardrail_configuration` block to the `aws_bedrockagent_agent` resource referencing the guardrail's `guardrail_identifier` and `guardrail_version`.
3. Test the agent thoroughly after adding the guardrail — overly strict filters can produce false-positive blocks on legitimate requests, so tune filter strengths iteratively.
4. Requires the AWS provider version that supports `aws_bedrock_guardrail` and the `guardrail_configuration` block on `aws_bedrockagent_agent`; verify your provider version supports these before applying.
5. This is generally an in-place update, but agent versioning/aliasing in Bedrock means you may need to create a new agent version/alias to roll out the guardrail change to production traffic.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/aws/BedrockGuardrails.py)
- [Amazon Bedrock Guardrails documentation](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html)
