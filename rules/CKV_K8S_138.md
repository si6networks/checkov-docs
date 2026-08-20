# CKV_K8S_138: Ensure that the --anonymous-auth argument is set to false
## Severity
**MEDIUM** (score: 5.0/10)

Enabling kubelet anonymous authentication lets unauthenticated requests reach the kubelet API, potentially allowing command execution in containers, log/metrics disclosure, and other privileged node-level actions without any credentials.

## Summary
This check verifies that `kubelet` explicitly disables anonymous authentication by setting `--anonymous-auth=false`, so unauthenticated requests to the kubelet API are rejected.

## Applicability
**Checkov framework(s):** `kubernetes`

Kubernetes manifests defining a Pod-carrying workload whose container `command` invokes `kubelet` — applicable entity kinds are `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. In practice this evaluates any manifest that surfaces kubelet's command-line invocation with its flags — per CIS Kubernetes Benchmark 4.2.1.

## Why it matters
The kubelet on each node exposes an HTTPS API (default port 10250) used for exec/attach/logs/port-forward and other node-management operations. If anonymous authentication is enabled (the historical default on some older distributions), requests without any credentials are treated as belonging to the `system:anonymous` user, which — depending on the authorization mode and any bound RBAC — may be able to query node information, list running pods, or in misconfigured setups invoke commands against containers on that node, all without presenting any identity. This is a direct node-compromise vector: an attacker with network access to the kubelet port on a node running with anonymous auth enabled may not need any valid cluster credential at all to interact with it. CIS Kubernetes Benchmark 4.2.1 requires `--anonymous-auth=false` on every kubelet.

## How Checkov evaluates this
The check (`KubeletAnonymousAuth`) inspects the container's `command` list:
- If `command` is absent, or does not include `kubelet`, the check **PASSES** (not applicable).
- If `kubelet` is present, it **FAILS** if either:
  - `--anonymous-auth=true` is present in `command`, **OR**
  - `--anonymous-auth=false` is *not* present in `command` (which also covers the flag being entirely absent).
- In other words, the check only **PASSES** when `--anonymous-auth=false` is explicitly and literally present — an absent flag is treated the same as `true` and fails.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubelet-config
  namespace: kube-system
spec:
  containers:
  - name: kubelet
    image: k8s.gcr.io/kubelet:v1.28.0
    command:
    - kubelet
    - --authorization-mode=Webhook
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kubelet-config
  namespace: kube-system
spec:
  containers:
  - name: kubelet
    image: k8s.gcr.io/kubelet:v1.28.0
    command:
    - kubelet
    - --authorization-mode=Webhook
    - --anonymous-auth=false
```

## Remediation steps
1. If kubelet is configured via a `KubeletConfiguration` file (the more common approach on modern clusters) rather than command-line flags, set `authentication.anonymous.enabled: false` in that config instead — Checkov's check here specifically scans command-line `command` arrays, so ensure whichever mechanism your cluster actually uses is set correctly.
2. If kubelet flags are set via command line (as this check inspects), add `--anonymous-auth=false` explicitly — do not rely on it being unset, since an absent flag fails this check and defaults may vary by distribution/version.
3. Ensure `--authorization-mode=Webhook` (or another non-`AlwaysAllow` mode) is also set, since disabling anonymous auth without proper authorization configured elsewhere can still leave gaps — the two settings work together.
4. Restart kubelet (`systemctl restart kubelet` on the node, or let the static Pod/DaemonSet-managed config propagate) after changing the setting.
5. Verify with `curl -k https://<node-ip>:10250/pods` (which should now be rejected without a valid credential) that anonymous requests are no longer served.

## References
- [Checkov check source](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeletAnonymousAuth.py)
- [Kubernetes kubelet authentication/authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
