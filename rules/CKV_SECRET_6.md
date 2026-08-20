# CKV_SECRET_6: Base64 High Entropy String

## Severity
**LOW** (score: 2.0/10)

A high-entropy base64 string flags likely hardcoded secret material, but as a generic heuristic detector (rather than a credential-type-specific match) it carries meaningfully more false-positive risk than a confirmed secret pattern, so it is rated just below outright confirmed-credential exposure.

## Summary
This check flags strings that look like base64-encoded blobs with unusually high Shannon entropy — a strong statistical signal that the string is a secret (key, token, password) rather than ordinary text or config data.

## Applicability
This is a built-in Checkov **secrets scanning** check (framework: `secrets`) that runs against any text file scanned in a repository or directory scan — YAML/JSON configs, IaC templates, shell scripts, Dockerfiles, netplan/cloud-init files, application source, etc. It is content-based, not tied to a specific resource type ("entities": `secrets`).

## Why it matters
High-entropy base64 strings are the classic fingerprint of an encoded secret: API keys, JWT signing keys, private key material, encryption keys, and hashed/derived passwords are frequently base64-encoded before being placed in config files, and their encoded form has entropy far higher than natural language or typical structured config values. An attacker who can read the repository (or a leaked file, backup, or log) can extract these strings directly and use them without needing to break any additional protection. In network configuration such as netplan files, a leaked value is often a device's actual Wi-Fi password or an interface authentication secret, and its exposure can lead to unauthorized access to a physical network segment — a real and often overlooked class of leak distinct from cloud API credentials.

## How Checkov evaluates this
Checkov delegates to the `detect-secrets` `Base64HighEntropyString` plugin. For each line scanned, the plugin extracts candidate substrings matching a base64-charset pattern and computes their Shannon entropy. If a candidate's entropy exceeds the plugin's configured threshold (tuned to separate typical base64 data — e.g. hashes, keys, tokens — from low-entropy incidental base64-looking text), the line is flagged as **FAILED** for `CKV_SECRET_6`. There is no resource-level pass/fail; a file with no high-entropy base64 substring simply produces no finding for this check.

## Non-compliant example
```yaml
# netplan config with an embedded high-entropy secret
network:
  version: 2
  wifis:
    wlan0:
      access-points:
        "HomeNetwork":
          password: "aGVsbG9Xb3JsZFRoaXNJc0FTZWNyZXRLZXkxMjM0NTY3ODkw"
```

## Remediated example
```yaml
# netplan config referencing a secret stored outside the file
network:
  version: 2
  wifis:
    wlan0:
      access-points:
        "HomeNetwork":
          password: "${WIFI_PSK}"   # rendered at provisioning time from a secrets store
```
```bash
# Secret is injected at image-build / provisioning time, e.g.:
export WIFI_PSK=$(vault kv get -field=psk secret/netplan/wlan0)
envsubst < 01-network-manager-all.yaml.tmpl > /etc/netplan/01-network-manager-all.yaml
```

## Remediation steps
1. Confirm whether the flagged string is a real secret; if so, treat it as compromised and rotate it (change the Wi-Fi PSK / regenerate the key) since it is likely already in git history.
2. Remove the literal value from the tracked file and template it in at provisioning/deploy time (cloud-init, Ansible vault, config management templating) rather than committing it.
3. Purge historical commits containing the secret using `git filter-repo` or BFG Repo-Cleaner — simply editing the current file leaves it recoverable from history.
4. Store the real value in a secrets manager or encrypted vault (e.g. Ansible Vault, SOPS, HashiCorp Vault) and reference it indirectly.
5. If a match is a verified false positive (e.g. a non-secret encoded blob, or an already-rotated/dummy test value), record it in a `detect-secrets` baseline (`detect-secrets scan --baseline .secrets.baseline`) rather than suppressing the check globally, so genuine future secrets are still caught.
6. Add pre-commit secret scanning so similar high-entropy leaks are blocked before merge, not just detected after the fact.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/common/bridgecrew/integration_features/features/policy_metadata_integration.py
