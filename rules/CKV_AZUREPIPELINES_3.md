# CKV_AZUREPIPELINES_3: Ensure set variable is not marked as a secret

## Severity
**HIGH** (score: 7.0/10)

Setting a variable without the secret flag causes its value to be written into pipeline logs and outputs in plaintext, risking direct disclosure of credentials or other sensitive values to anyone with log access.

## Summary
This check fails when a `bash` or `powershell` pipeline step uses the `##vso[task.setvariable]` logging command with `issecret=true` — i.e., a script-computed value is being marked as a secret variable at runtime, which Checkov flags for review.

## Applicability
- **Azure Pipelines** YAML pipeline definitions — applies to `jobs[].steps[]` and `stages[].jobs[].steps[]` entities, specifically inline `bash` or `powershell` step scripts.

## Why it matters
Azure Pipelines lets a script dynamically mark a variable as secret using `echo "##vso[task.setvariable variable=myVar;issecret=true]<value>"`, which causes the pipeline to mask that value in subsequent log output. However, this pattern is inherently fragile as a security control: the value is computed and briefly exposed in plaintext within the script itself before being marked secret, it can end up in shell history, temp files, or earlier log lines depending on how the script is written, and masking is best-effort string-matching on log output — it does not prevent the value from being captured via other means (e.g., writing it to an artifact, an unmasked debug step, or a variable dependent on it elsewhere in the pipeline). Checkov flags any use of this pattern because dynamically-created "secrets" set this way are much easier to leak by accident than variables declared through Azure DevOps' actual secret variable groups or a proper secrets manager (Azure Key Vault), which never expose the plaintext value to the pipeline log or script surface in the first place.

## How Checkov evaluates this
For each step, the check reads the `bash` or `powershell` inline script text. It scans line by line for the substring `task.setvariable`. If found on a line, `variable_found = True`; if that same line also contains `issecret=true` → **FAILED** immediately. If the loop completes having found at least one `task.setvariable` line but none with `issecret=true` → **PASSED**. If no `task.setvariable` usage is found in the script at all → **UNKNOWN** (the check doesn't apply to this step).

## Non-compliant example
```yaml
steps:
  - bash: |
      TOKEN=$(curl -s https://internal-service/token)
      echo "##vso[task.setvariable variable=apiToken;issecret=true]$TOKEN"
    displayName: 'Fetch and mask token'
```

## Remediated example
```yaml
steps:
  - task: AzureKeyVault@2
    inputs:
      azureSubscription: 'my-service-connection'
      KeyVaultName: 'my-keyvault'
      SecretsFilter: 'apiToken'
    displayName: 'Fetch token from Key Vault'

  - bash: |
      echo "Using token from Key Vault variable: $(apiToken)"
    displayName: 'Use token'
```

## Remediation steps
1. Avoid computing sensitive values inline in a script and marking them secret with `##vso[task.setvariable ...;issecret=true]` after the fact — the plaintext value still transits the script and its environment before masking kicks in.
2. Use the `AzureKeyVault@2` task (or an equivalent secrets-manager integration) to pull secrets directly into pipeline variables, which are automatically treated as secret and never exposed to script logic in plaintext form.
3. For values that genuinely must be generated at runtime (e.g., a short-lived token from an internal service), store them in a proper secret store immediately rather than passing them through a masked pipeline variable, and scope their lifetime/visibility as tightly as possible.
4. Review pipeline logs and step outputs surrounding any `task.setvariable` usage for accidental earlier exposure of the value (e.g., in a preceding `echo`/`Write-Host` for debugging).

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/azure_pipelines/checks/job/SetSecretVariable.py
- Azure Pipelines docs on logging commands: https://learn.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands
