# CKV_K8S_78: Ensure that the admission control plugin EventRateLimit is set
## Severity
**MEDIUM** (score: 5.0/10)

Without the EventRateLimit admission plugin the API server has no throttling on event-generating requests, leaving it exposed to resource-exhaustion/denial-of-service from malicious or malfunctioning clients.

## Summary
This check fails an `AdmissionConfiguration` resource unless it includes a plugin entry named `EventRateLimit`, which throttles the rate of requests the API server accepts, protecting it from being overwhelmed.

## Applicability
Kubernetes manifests of kind `AdmissionConfiguration` (the `apiserver.config.k8s.io` `AdmissionConfiguration` file that configures admission plugins, referenced via `kube-apiserver --admission-control-config-file`).

## Why it matters
The `EventRateLimit` admission controller limits the rate of requests the API server processes per identified source (server overall, namespace, user, or source+object combination). Without it, a misbehaving controller, a compromised workload, or a flood of legitimate events (e.g., a crash-looping pod generating thousands of `Event` objects per second) can overwhelm the API server and, transitively, etcd — leading to control-plane unavailability, missed scheduling decisions, and cascading cluster-wide outages. This is a defense against both accidental self-inflicted denial-of-service (noisy workloads) and deliberate resource-exhaustion attacks against the API server. It's called out in the CIS Kubernetes Benchmark as a recommended admission plugin (1.2.13 or similar depending on version), though it is disabled by default and requires an explicit `AdmissionConfiguration` file plus `--enable-admission-plugins=EventRateLimit`.

## How Checkov evaluates this
`ApiServerAdmissionControlEventRateLimit.py` (a `BaseK8Check` for `AdmissionConfiguration`): if the resource's `plugins` key is missing → FAILED. Otherwise it iterates `plugins`, checking each entry's `name`; if any plugin has `name == "EventRateLimit"` → PASSED; if the loop completes without finding one → FAILED.

## Non-compliant example
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "baseline"
# EventRateLimit plugin entry missing -> FAILS
```

## Remediated example
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: PodSecurity
  configuration:
    apiVersion: pod-security.admission.config.k8s.io/v1
    kind: PodSecurityConfiguration
    defaults:
      enforce: "baseline"
- name: EventRateLimit
  path: /etc/kubernetes/admission/eventconfig.yaml
```

The referenced `eventconfig.yaml` (an `EventRateLimitConfiguration`, not scanned by this check) would look like:
```yaml
apiVersion: eventratelimit.admission.k8s.io/v1alpha1
kind: Configuration
limits:
- type: Server
  qps: 5000
  burst: 20000
```

## Remediation steps
1. Add an entry to the `AdmissionConfiguration.plugins` list with `name: EventRateLimit`, pointing `path` at a separate `EventRateLimitConfiguration` file defining limit types (`Server`, `Namespace`, `User`, `SourceAndObject`) and their `qps`/`burst` values.
2. Ensure `--enable-admission-plugins=EventRateLimit` (or that it's included in the default enabled set for your Kubernetes version) is passed to `kube-apiserver`, and `--admission-control-config-file` points at the file containing this `AdmissionConfiguration`.
3. Size the rate limits conservatively based on expected event volume in your cluster to avoid throttling legitimate traffic — start permissive and tighten based on observed metrics (`apiserver_admission_controller_admission_latencies_seconds` and related admission metrics).
4. Restart the API server after changing the admission configuration file (static pod manifests will trigger this automatically on file change).
5. Re-scan with `checkov -d . --check CKV_K8S_78`.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerAdmissionControlEventRateLimit.py)
- [Kubernetes Admission Controllers reference](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#eventratelimit)
