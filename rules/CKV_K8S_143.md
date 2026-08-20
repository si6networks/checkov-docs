# CKV_K8S_143: Ensure that the --streaming-connection-idle-timeout argument is not set to 0
## Severity
**LOW** (score: 2.0/10)

Setting the streaming-connection idle timeout to 0 keeps kubelet exec/attach/port-forward streaming connections open indefinitely, letting a hijacked or stale session persist unauthorized access longer than necessary.

## Summary
This check ensures the kubelet's `--streaming-connection-idle-timeout` is not explicitly disabled (set to `0`), which would let streaming connections (exec/attach/portforward) stay open indefinitely.

## Applicability
Kubernetes manifests for workload kinds carrying a pod template: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. It inspects the container `command` array, acting when it invokes `kubelet`.

## Why it matters
`--streaming-connection-idle-timeout` controls how long an idle streaming connection to the kubelet (used for `kubectl exec`, `attach`, `logs -f`, `port-forward`) is kept open before being closed. Setting it to `0` disables the timeout entirely, meaning idle connections never expire. This increases the attack surface for connection hijacking and resource exhaustion: an attacker who gains or steals a streaming session (or an unattended/forgotten session) can retain an open channel indefinitely rather than having it forcibly terminated, giving them a longer window to act, and abandoned connections can accumulate and consume kubelet resources. CIS Kubernetes Benchmark control 4.2.5 recommends leaving this at its non-zero default (or an explicit reasonable value) rather than disabling the timeout.

## How Checkov evaluates this
The check (`KubeletStreamingConnectionIdleTimeout`) looks at each container's `command` list:
1. If `kubelet` is among the command tokens, it checks whether the literal string `--streaming-connection-idle-timeout=0` appears anywhere in the command list.
2. If it does, the check **FAILS**.
3. Otherwise (flag absent, or set to any non-zero value), the check **PASSES**. Note the match is an exact string match on `=0`, not a general numeric-value comparison.

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
        - --streaming-connection-idle-timeout=0
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
        - --streaming-connection-idle-timeout=4h
```

## Remediation steps
1. Remove any `--streaming-connection-idle-timeout=0` flag from the kubelet command line, or set it to a positive duration such as `4h` (Kubernetes default) or a value appropriate to your operational needs (shorter for higher-security environments).
2. If using the `KubeletConfiguration` file, ensure `streamingConnectionIdleTimeout` is not set to `"0s"`.
3. Roll the change out per node and restart the kubelet; validate that legitimate long-running `kubectl exec`/`port-forward` sessions still behave as expected within the new timeout window.
4. Balance operational convenience (very long debug sessions) against the security benefit of shorter timeouts; align with your organization's session-timeout policy.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubeletStreamingConnectionIdleTimeout.py
