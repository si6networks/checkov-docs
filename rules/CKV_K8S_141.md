# CKV_K8S_141: Ensure that the --read-only-port argument is set to 0
## Severity
**HIGH** (score: 7.5/10)

Leaving the kubelet's unauthenticated read-only port (10255) open exposes pod and node metadata, and in some configurations exec/logs, to anyone with network access, without any authentication.

## Summary
This check ensures the kubelet's unauthenticated, read-only HTTP port (`--read-only-port`) is disabled by setting it to `0`.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests for workload kinds carrying a pod template: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. It inspects the container `command` array, acting when it invokes `kubelet`.

## Why it matters
The kubelet's read-only port (default 10255) serves a subset of the kubelet API over plain HTTP with **no authentication or authorization** whatsoever. Anything reachable on that port — pod specs, running container details, node metrics — is exposed to anyone with network access to the node, no credentials required. This can leak sensitive configuration (environment variable names, mounted volume paths, image names) that aids an attacker in further compromise, and in some configurations has been used for reconnaissance and node fingerprinting in real-world Kubernetes attacks (e.g., cryptomining worm campaigns that scan for open kubelet ports). CIS Kubernetes Benchmark control 4.2.4 requires this port be disabled (`--read-only-port=0`) so that all kubelet API interaction goes through the authenticated, authorized HTTPS port instead.

## How Checkov evaluates this
The check (`KubeletReadOnlyPort`) uses a helper `extract_commands` to parse the container's `command` list into flag/value pairs:
1. If `kubelet` is among the parsed keys (i.e., is one of the command tokens), it checks whether `--read-only-port` is also present.
2. If `--read-only-port` is present and its value equals the string `"0"`, the check **PASSES**.
3. If `--read-only-port` is present with any other value, or `kubelet` is invoked but `--read-only-port` is absent entirely, the check **FAILS** — i.e., the flag must be explicitly present and set to `0`; there's no benefit-of-the-doubt default.
4. If the command doesn't invoke `kubelet` at all, the check **PASSES** (not applicable).

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubelet-static-pod
spec:
  containers:
    - name: kubelet
      image: k8s.gcr.io/hyperkube:v1.20.0
      command:
        - kubelet
        - --read-only-port=10255
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubelet-static-pod
spec:
  containers:
    - name: kubelet
      image: k8s.gcr.io/hyperkube:v1.20.0
      command:
        - kubelet
        - --read-only-port=0
```

## Remediation steps
1. Add or change `--read-only-port` on the kubelet's command line to `--read-only-port=0` (or set `readOnlyPort: 0` in the `KubeletConfiguration` file if flags are being replaced by a config file).
2. Verify nothing in your monitoring/tooling stack depends on the unauthenticated read-only port (e.g., legacy scrapers hitting `:10255/metrics`) — migrate such consumers to the authenticated HTTPS kubelet endpoint or to `kube-state-metrics`/`metrics-server`.
3. Roll out the change and restart the kubelet per node; validate node `Ready` status and that metrics/log collection continue to function via the authenticated path.
4. Firewall/network-policy the kubelet ports regardless, as defense in depth even after disabling the read-only port.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeletReadOnlyPort.py
