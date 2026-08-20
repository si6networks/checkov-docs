# CKV_K8S_140: Ensure that the --client-ca-file argument is set as appropriate
## Severity
**LOW** (score: 2.0/10)

Without a --client-ca-file, the kubelet cannot validate client certificates for authenticated API requests, weakening node-level authentication and easing unauthorized access to kubelet endpoints.

## Summary
This check ensures the kubelet is configured with a `--client-ca-file` pointing to a non-empty value, so client certificate authentication for requests to the kubelet API is enabled.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests for workload kinds carrying a pod template: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. It inspects the container `command` array, acting only when the command invokes `kubelet` (kubelet static-pod / wrapper manifests).

## Why it matters
The `--client-ca-file` flag tells the kubelet which CA to trust when validating client certificates presented by callers of its HTTPS API. Without a valid client CA configured, the kubelet cannot perform certificate-based client authentication, weakening the authentication layer that normally works together with `--authorization-mode=Webhook` to ensure only legitimate, RBAC-authorized principals (typically the API server) can invoke kubelet operations such as exec, logs, and portforward. If this is unset or empty, an attacker with network reachability to the kubelet port may be able to interact with it without presenting a trusted client certificate, undermining node-level security controls and enabling lateral movement or data exposure. This maps to CIS Kubernetes Benchmark control 4.2.3.

## How Checkov evaluates this
The check (`KubeletClientCa`) looks at each container's `command` list:
1. If `kubelet` is in the command, it scans for an argument starting with `--client-ca-file`.
2. If found and it has the form `--client-ca-file=<value>` with a non-empty (after stripping whitespace) value, the check **PASSES**.
3. If found but the value is empty/blank, or the argument has no `=value` at all, it **FAILS**.
4. If `kubelet` is invoked but no `--client-ca-file` argument appears at all, it **FAILS**.
5. If the command doesn't invoke kubelet, the result is `UNKNOWN` (not applicable).

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
        - --authorization-mode=Webhook
        # --client-ca-file missing entirely
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
        - --authorization-mode=Webhook
        - --client-ca-file=/etc/kubernetes/pki/ca.crt
```

## Remediation steps
1. Determine the path to the cluster's CA certificate that signed client certificates used to authenticate to the kubelet (often the same CA used by the API server, e.g. `/etc/kubernetes/pki/ca.crt`).
2. Set `--client-ca-file=/etc/kubernetes/pki/ca.crt` (or the appropriate path) in the kubelet invocation, or the equivalent `authentication.x509.clientCAFile` field in the `KubeletConfiguration` file if using the config-file mechanism instead of flags.
3. Verify the file exists and is readable by the kubelet process on every node before rolling this out — a bad path will prevent the kubelet from starting.
4. Restart the kubelet per node; this is a node-level control-plane component change, so stage the rollout and monitor node readiness during the change.
5. On managed Kubernetes (EKS/GKE/AKS), this is typically configured by the provider already; this check is most relevant for self-managed/on-prem clusters.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeletClientCa.py
