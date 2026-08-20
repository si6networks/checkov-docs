# CKV_K8S_95: Ensure that the --request-timeout argument is set as appropriate
## Severity
**MEDIUM** (score: 5.0/10)

Missing request timeouts on the API server are primarily an availability/resource-exhaustion concern, as long-lived or slow requests can tie up server resources, rather than a direct confidentiality or authorization gap.

## Summary
This check verifies that if a self-managed `kube-apiserver` container sets `--request-timeout`, the value is a well-formed duration string (e.g., `1m`, `30s`, `1h30m`).

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests only. Applies to pod-spec-bearing resources: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. Relevant only to the container spec of a self-hosted `kube-apiserver` static pod/manifest.

## Why it matters
`--request-timeout` bounds how long the API server will wait before timing out a request. Extremely long or unbounded timeouts allow slow, hung, or maliciously slow-drip requests (a form of resource-exhaustion / slowloris-style attack) to tie up API server worker goroutines and connections indefinitely, contributing to control-plane resource exhaustion and reduced availability for legitimate clients. An unparseable or malformed value can also cause `kube-apiserver` to fail to start or fall back to undocumented behavior, which is an operational risk in itself. Setting a sane, well-formed timeout value is part of standard API server hardening to bound worst-case resource consumption per request.

## How Checkov evaluates this
The check (`ApiServerRequestTimeout`, a `BaseK8sContainerCheck`) inspects the container's `command` list using this timeout regex: `^(\d{1,2}[h])(\d{1,2}[m])?(\d{1,2}[s])?$|^(\d{1,2}[m])?(\d{1,2}[s])?$|^(\d{1,2}[s])$`
1. If `command` is not a list, or doesn't contain `kube-apiserver`, returns PASSED.
2. If `kube-apiserver` is present, it scans each argument:
   - A bare `--request-timeout` with no value → FAILED.
   - `--request-timeout=<value>` → FAILED unless `<value>` matches the duration regex above (1-2 digit hour/minute/second components, e.g. `1h30m`, `30s`, `5m`).
3. If `--request-timeout` is never set at all, the check returns PASSED by default (an absent flag isn't flagged; only a malformed value is).

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      image: registry.k8s.io/kube-apiserver:v1.29.0
      command:
        - kube-apiserver
        - --request-timeout=infinite
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      image: registry.k8s.io/kube-apiserver:v1.29.0
      command:
        - kube-apiserver
        - --request-timeout=1m
```

## Remediation steps
1. Set `--request-timeout` to a valid Go-style duration string composed of 1–2 digit hour/minute/second segments, such as `1m` (the Kubernetes default), `30s`, or `1h30m`.
2. Avoid non-numeric or malformed values (e.g., `infinite`, `0`, values with 3+ digit components) — these will fail the check and may also be rejected by `kube-apiserver` itself at startup.
3. If you rely on long-running API requests (e.g., large `watch` or `list` calls, streaming logs), be aware `--request-timeout` applies to non-streaming requests; tune it based on your workload's actual request latency profile rather than setting it arbitrarily high.
4. If the flag is omitted, `kube-apiserver` uses its built-in default (1 minute) — omitting it is a valid, compliant choice per this check.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/ApiServerRequestTimeout.py)
- [Kubernetes API server options reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
