# raspbernetes/k8s-security-policies

- Upstream: https://github.com/raspbernetes/k8s-security-policies
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `39e822e5dc6c19adb50bdb123dec6b8b3cba5ca8`
- Imported files: 64 `.rego` files from `policies/` (tests stripped)

## What these rules cover

A comprehensive CIS-Kubernetes-benchmark-aligned policy library for hardening
cluster configurations. Two policy families are bundled:

| Family | Rules | Scope |
|---|---:|---|
| CIS.1.2.x | 19 | API server flags (`--anonymous-auth`, `--authorization-mode`, `--audit-log-*`, `--encryption-provider-config`, etc.) |
| CIS.1.3.x | 7 | Controller manager flags (`--use-service-account-credentials`, `--service-account-private-key-file`, etc.) |
| CIS.1.4.x | 2 | Scheduler flags (`--profiling`, `--bind-address`) |
| CIS.2.x | 7 | etcd config (`--cert-file`, `--key-file`, `--client-cert-auth`, `--auto-tls`, `--peer-*`) |
| CIS.5.1.x | 5 | RBAC / service accounts (cluster-admin, minimal roles, default SA usage) |
| CIS.5.2.x | 5 | PodSecurityPolicy / PSS (privileged, hostPID/IPC/Network, privilege escalation) |
| CIS.5.4.1 | 1 | Default namespace not in active use |
| CIS.5.5.1 | 1 | Image provenance / signing |
| K.SEC.01–15 | 15 | Kubesec.io rules (resource limits, readOnlyRootFilesystem, runAsNonRoot, securityContext, network policies, labels, probes, imagePullPolicy, allowPrivilegeEscalation, capabilities, serviceAccountToken automount, etc.) |

Policies use the `violation[msg]` convention. Each rule has its own package
(e.g., `cis_1_2_1`, `containers_resources_limits_cpu`).

## Layout

```
raspbernetes-k8s-security-policies/
└── policies/
    ├── lib/
    │   └── kubernetes.rego           # shared helpers: containers[], apiserver[], format(), name/kind/namespace
    ├── CIS.1.2.1/CIS.1.2.1.rego      # one folder per control
    ├── CIS.1.2.2/CIS.1.2.2.rego
    ├── …
    ├── CIS.5.5.1/CIS.5.5.1.rego
    ├── K.SEC.01/K.SEC.01.rego
    ├── …
    └── K.SEC.15/K.SEC.15.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

The library's `object` binding is **dual-mode** — it unwraps Gatekeeper
`input.review.object` when present, otherwise falls back to raw `input`:

```rego
object = input {
    not is_gatekeeper
}
object = input.review.object {
    is_gatekeeper
}
```

This means the same rules work for:

- **Local K8s manifest files** (e.g., `/etc/kubernetes/manifests/kube-apiserver.yaml`, Deployments, Pods) fed directly as `input` — ideal for static scanning.
- Admission-controller webhooks (Gatekeeper) when deployed in-cluster.

Purely local: no cluster API calls, no HTTP fetches from rule code.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that
parses each `*.yaml` manifest and evaluates it as the rule's `input`.

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter required to hand each parsed K8s manifest to the rules.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via conftest (for local manifests):
conftest test --policy rules/raspbernetes-k8s-security-policies/policies ./manifests

# Or with OPA:
opa eval -d rules/raspbernetes-k8s-security-policies/policies \
  -i my-deployment.json "data[_].violation"
```

## Attribution

Copyright raspbernetes and the k8s-security-policies contributors. Licensed
under the Apache License, Version 2.0. See `LICENSE`.
