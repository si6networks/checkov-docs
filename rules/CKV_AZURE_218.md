# CKV_AZURE_218: Ensure Application Gateway defines secure protocols for in transit communication
## Severity
**HIGH** (score: 7.5/10)

Allowing outdated TLS versions or deprecated/weak cipher suites on an Application Gateway undermines transport encryption, exposing in-transit traffic to downgrade and interception attacks.

## Summary
Ensures that an Azure Application Gateway's SSL/TLS policy enforces a modern minimum TLS protocol version (TLS 1.2 or 1.3) and does not permit legacy/weak cipher suites, when using a custom (non-predefined) SSL policy — or uses Microsoft's current recommended predefined policy.

## Applicability
**Checkov framework(s):** `arm`, `bicep`, `terraform`

- **Terraform**: `azurerm_application_gateway` — inspects the `ssl_policy` block (`policy_type`, `min_protocol_version`, `cipher_suites`, `policy_name`)
- **ARM**: `Microsoft.Network/applicationGateways` — inspects `properties.sslPolicy` (`policyType`, `minProtocolVersion`, `cipherSuites`, `policyName`)
- **Bicep**: compiles to the ARM resource type above

## Why it matters
The TLS handshake protocol and cipher suite negotiated between clients and the gateway determine the actual cryptographic strength protecting data in transit. Older TLS versions (TLS 1.0/1.1) and legacy cipher suites (e.g., CBC-mode ciphers vulnerable to padding-oracle attacks like POODLE/BEAST, or ciphers using weak key exchange such as 3DES or non-ephemeral RSA key exchange lacking forward secrecy) have known cryptographic weaknesses that can allow an attacker with network visibility to decrypt or tamper with supposedly-encrypted traffic. Compliance frameworks (PCI-DSS since v3.1, NIST, and most enterprise security baselines) explicitly require disabling TLS below 1.2. Application Gateway's `Predefined` SSL policies are Microsoft-curated bundles that are updated over time to drop deprecated ciphers; using an outdated predefined policy name or a hand-rolled `Custom`/`CustomV2` policy that still allows weak ciphers or an old minimum protocol version leaves the gateway needlessly exposed to protocol-downgrade and cipher-weakness attacks.

## How Checkov evaluates this
The check reads `sslPolicy`/`ssl_policy`:
1. If `policyType` is **not** `"Predefined"` (i.e., it's `Custom` or `CustomV2`):
   - It checks `minProtocolVersion`/`min_protocol_version` is one of `TLSv1_2` or `TLSv1_3`.
   - If so, it then checks `cipherSuites`/`cipher_suites` against a hard-coded `BAD_CIPHERS` set (legacy CBC-mode, 3DES, and non-ephemeral RSA key-exchange suites). If any listed cipher is present, the check **FAILS**; otherwise it **PASSES**.
   - If the minimum protocol version isn't TLS 1.2/1.3, or isn't set, the check falls through to check `policyName`.
2. If `policyType` **is** `"Predefined"` (or the above branch didn't pass): it checks `policyName`/`policy_name`. Only the specific value `"AppGwSslPolicy20220101S"` (Microsoft's current strict predefined policy) causes a **PASS**; any other predefined policy name, or a missing `ssl_policy` block entirely, **FAILS**.

## Non-compliant example
```hcl
resource "azurerm_application_gateway" "example" {
  name                = "example-appgw"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  # ... other required blocks omitted ...

  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20170401"   # outdated predefined policy
  }
}
```

## Remediated example
```hcl
resource "azurerm_application_gateway" "example" {
  name                = "example-appgw"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location

  # ... other required blocks omitted ...

  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101S"   # current strict predefined policy, TLS 1.2+ only
  }
}
```

## Remediation steps
1. Prefer using the latest Microsoft-managed predefined policy `AppGwSslPolicy20220101S`, which enforces TLS 1.2+ and excludes weak ciphers, and is updated by Microsoft as standards evolve.
2. If a custom policy is required (e.g., to support a specific legacy client that cannot be upgraded — generally discouraged), set `policy_type = "CustomV2"` (or `"Custom"`), `min_protocol_version = "TLSv1_2"` or `"TLSv1_3"`, and select only strong `cipher_suites` (AEAD ciphers such as `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`; avoid anything in CBC mode or 3DES).
3. Test client compatibility after changing the policy, since very old clients (e.g., legacy embedded devices, old Java/.NET HTTP clients) may not support TLS 1.2+ and will fail to connect — plan a migration path for such clients rather than weakening the policy.
4. Periodically re-check Microsoft's predefined policy recommendations, since new predefined policy versions are released as cryptographic best practices evolve.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/arm/checks/resource/AppGWDefinesSecureProtocols.py
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppGWDefinesSecureProtocols.py
- Azure docs: https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-ssl-policy-overview
