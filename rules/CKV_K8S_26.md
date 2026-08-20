# CKV_K8S_26: Do not specify hostPort unless absolutely necessary
## Severity
**LOW** (score: 2.0/10)

Binding a container port directly to the host bypasses the Service/network-policy abstraction and can inadvertently expose an internal service on the node's network, but it does not itself grant elevated privileges.

## Summary
This check fails any container port definition that includes `hostPort`, because binding a container port directly to a specific port on the node reduces scheduling flexibility and exposes the container's service to anything on the node's network.

## Applicability
**Checkov framework(s):** `kubernetes`, `terraform`

- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `PodTemplate`, `Deployment`, `DeploymentConfig`, `ReplicaSet`, `ReplicationController`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`

## Why it matters
Setting `hostPort` on a container port binds that port directly on the node's network interface(s), similar in effect to (though narrower than) `hostNetwork`. This has two consequences relevant to security and reliability. First, scheduling: each `<hostIP, hostPort, protocol>` combination must be unique across the node, so using `hostPort` limits how many replicas of a pod can be scheduled per node and can cause scheduling failures as the cluster fills up. Second, and more security-relevant: the bound port becomes reachable via the node's IP directly, bypassing the usual Service/Ingress-based access path and any NetworkPolicy that's scoped to the pod network rather than host-level exposure. This means a `hostPort` can inadvertently make an internal-only service reachable from outside the intended network boundary (e.g. if the node has a public IP, or from any other pod on the node bypassing Service-level access controls), and complicates auditing what is actually exposed at the node level.

## How Checkov evaluates this
- **Kubernetes-native (`HostPort`):** for each container, checks each entry in `ports`. If any port entry contains a `hostPort` key at all (regardless of value), FAILED. No `ports` or no `hostPort` key → PASSED.
- **Terraform (`HostPort`):** inspects `spec[0].container[*].port[*].host_port` (following `template[0].spec[0]` for Deployments). If any `port` block contains a `host_port` key, FAILED.

## Non-compliant example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: legacy-app
spec:
  containers:
    - name: app
      image: myorg/app:1.0
      ports:
        - containerPort: 8080
          hostPort: 8080
```

## Remediated example
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: legacy-app
spec:
  containers:
    - name: app
      image: myorg/app:1.0
      ports:
        - containerPort: 8080
          # hostPort removed -> access via a Service instead
```
```yaml
apiVersion: v1
kind: Service
metadata:
  name: legacy-app-svc
spec:
  selector:
    app: legacy-app
  ports:
    - port: 8080
      targetPort: 8080
```

## Remediation steps
1. Remove `hostPort` from container port definitions.
2. Expose the workload instead through a Kubernetes `Service` (ClusterIP for internal access, or LoadBalancer/NodePort with an explicit, reviewed exposure boundary, plus an Ingress controller for HTTP(S) traffic) rather than binding directly to the node.
3. If `hostPort` was used for host-level networking requirements (e.g. a DaemonSet needing a fixed, well-known port on every node, such as a monitoring agent), confirm this is a genuine requirement and, if so, scope it to a dedicated, reviewed DaemonSet rather than a general application workload.
4. Re-test scheduling after removal — pods should now be schedulable with higher replica density per node since the host port uniqueness constraint no longer applies.
5. Verify no external firewall rules or network expectations assumed the previous host-level port binding before removing it in production.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/HostPort.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/HostPort.py)
- [Kubernetes: Configuration Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
