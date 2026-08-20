# CKV_K8S_147: Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture
## Severity
**LOW** (score: 2.0/10)

An excessive --event-qps rate limit degrades kubelet event capture used for security monitoring and incident investigation, reducing visibility into node-level activity rather than enabling direct compromise.

## Summary
This check ensures the kubelet's `--event-qps` rate limit (queries-per-second for event reporting) is not set so high that meaningful audit/event data could be dropped or rate-limited away — anything over 5 is flagged.

## Applicability
Kubernetes manifests for workload kinds carrying a pod template: `CronJob`, `DaemonSet`, `Deployment`, `DeploymentConfig`, `Job`, `Pod`, `PodTemplate`, `ReplicaSet`, `ReplicationController`, `StatefulSet`. It inspects the container `command` array, acting when it invokes `kubelet`.

## Why it matters
`--event-qps` throttles how many event API calls per second the kubelet is allowed to make when reporting node/pod events to the API server. This limit exists to protect the API server from being overwhelmed, but setting it too high defeats the purpose of the throttle and — more importantly from a security lens — the CIS benchmark's intent is to ensure organizations deliberately choose a rate that guarantees important events (e.g., security-relevant events like repeated container crashes, image pull failures, or OOM kills) are captured, not silently dropped due to overly aggressive limiting. Excessively high or ungoverned settings without a considered value can either flood the API server (a reliability/DoS risk to the control plane) or, if implicitly relied on as "unlimited," fail to actually guarantee capture, undermining the ability to detect and respond to anomalous node/pod behavior. CIS Kubernetes Benchmark 4.2.9 recommends explicitly setting this to `0` (unlimited, capture everything) or another deliberately chosen value appropriate to your environment — this check flags overly large arbitrary values (>5) as likely unconsidered/misconfigured.

## How Checkov evaluates this
The check (`KubletEventCapture`) looks at each container's `command` list:
1. If `kubelet` is among the command tokens, it iterates the command arguments looking for ones containing `=`.
2. For any argument whose key (before the first `=`) is `--event-qps`, it parses the value as an integer.
3. If that integer value is greater than `5`, the check **FAILS**.
4. Otherwise (value ≤ 5, including `0`, or the flag isn't present at all), the check **PASSES**.
Note: a non-integer value would raise a `ValueError` in the underlying code rather than a graceful `UNKNOWN`, so malformed values could cause a scan error rather than a clean result.

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
        - --event-qps=50
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
        - --event-qps=0
```

## Remediation steps
1. Decide, per your organization's monitoring/logging capacity, whether you want unlimited event capture (`--event-qps=0`) or a deliberately chosen bounded rate ≤5.
2. Set `--event-qps` accordingly on the kubelet command line, or `eventRecordQPS` in the `KubeletConfiguration` file.
3. If setting to `0` (unlimited), ensure your API server and etcd can handle the increased event volume, especially on large/noisy clusters — monitor API server load after the change.
4. Roll out per node and confirm event visibility (e.g., via `kubectl get events` or your event-forwarding pipeline) reflects the expected volume post-change.

## References
- Checkov check source: https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/KubletEventCapture.py
