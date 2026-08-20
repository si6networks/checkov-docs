# CKV_K8S_27: Do not expose the docker daemon socket to containers
## Severity
**MEDIUM** (score: 5.0/10)

Mounting the Docker daemon socket into a container gives it root-equivalent control over the host's container runtime, making full host compromise trivial for anything running in that container.

## Summary
This check fails any Pod/workload that mounts a `hostPath` volume pointing at `/var/run/docker.sock`, because giving a container access to the Docker daemon socket is equivalent to giving it root access to the entire host.

## Applicability
- **IaC framework:** Kubernetes manifests (YAML/JSON) and Terraform
- **Resource/entity types (Kubernetes):** `Pod`, `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet`, `ReplicationController`, `Job`, `CronJob`
- **Resource/entity types (Terraform):** `kubernetes_pod`, `kubernetes_pod_v1`, `kubernetes_deployment`, `kubernetes_deployment_v1`, `kubernetes_daemonset`, `kubernetes_daemon_set_v1`

## Why it matters
The Docker daemon socket (`/var/run/docker.sock`) is the control interface for the Docker Engine, and any process that can talk to it can instruct Docker to do essentially anything the daemon itself can do — including starting a new container with the host's root filesystem bind-mounted and no isolation, effectively achieving full root code execution on the node. This pattern is a well-known and heavily abused technique ("docker-socket-mount to root") used both for legitimate Docker-in-Docker CI/build tooling and, when misused or exploited, for container escapes: mounting a `--privileged` container with `-v /var/run/docker.sock:/var/run/docker.sock` and `-v /:/host` from inside a compromised container gives full host takeover in a few commands. Mounting the docker socket read-only does not meaningfully reduce this risk — the Docker API itself allows creating and starting new privileged containers regardless of how the socket file was mounted, so "read-only" only prevents deleting the socket file, not abusing the API behind it.

## How Checkov evaluates this
- **Kubernetes-native (`DockerSocketVolume`):** resolves the effective `spec` (directly for `Pod`, via `spec.jobTemplate.spec.template.spec` for `CronJob`, via `spec.template.spec` otherwise) and iterates `spec.volumes`. If any volume has `hostPath.path == "/var/run/docker.sock"`, FAILED.
- **Terraform (`DockerSocketVolume`):** checks `spec[0].volume[*].host_path[0].path` both at the top-level `spec` and under `spec[0].template[0].spec[0].volume[*]`. If any equals `["/var/run/docker.sock"]`, FAILED.

## Non-compliant example
```hcl
resource "kubernetes_deployment" "nuclio_dashboard" {
  metadata {
    name = "nuclio-dashboard"
  }
  spec {
    template {
      spec {
        container {
          name  = "dashboard"
          image = "nuclio/dashboard:latest"
          volume_mount {
            name       = "docker-sock"
            mount_path = "/var/run/docker.sock"
          }
        }
        volume {
          name = "docker-sock"
          host_path {
            path = "/var/run/docker.sock"
          }
        }
      }
    }
  }
}
```

## Remediated example
```hcl
resource "kubernetes_deployment" "nuclio_dashboard" {
  metadata {
    name = "nuclio-dashboard"
  }
  spec {
    template {
      spec {
        container {
          name  = "dashboard"
          image = "nuclio/dashboard:latest"
          # docker.sock volume mount removed entirely
        }
        # host_path volume for docker.sock removed
      }
    }
  }
}
```

## Remediation steps
1. Remove the `host_path`/`hostPath` volume pointing at `/var/run/docker.sock` from the `nuclio-serverless.tf` and `traefik-ingress.tf` deployment resources in `src/cloud/infra/terraform/perception_and_prediction/servespector/deployments/`.
2. If the workload needs to build/run containers (e.g. Nuclio's serverless function builder), replace direct docker-socket access with a rootless, sandboxed builder such as Kaniko, Buildkit-in-rootless-mode, or img, none of which require daemon socket access.
3. If Traefik's docker-socket mount was for a Docker-provider-based dynamic configuration, switch Traefik to the Kubernetes provider (CRDs/Ingress) instead of the Docker provider, since it is running on Kubernetes and does not need direct Docker API access.
4. Where node-level container introspection is genuinely required (e.g. a monitoring/security agent), use the read-only containerd/CRI socket with a narrowly scoped, purpose-built client rather than the full Docker Engine API, and run it as a dedicated, tightly access-controlled DaemonSet.
5. Enforce with an admission controller (Kyverno/OPA Gatekeeper) blocking `hostPath` volumes referencing `/var/run/docker.sock` cluster-wide.

## References
- [Checkov check source (Kubernetes)](https://github.com/bridgecrewio/checkov/blob/main/checkov/kubernetes/checks/resource/k8s/DockerSocketVolume.py)
- [Checkov check source (Terraform)](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/kubernetes/DockerSocketVolume.py)
