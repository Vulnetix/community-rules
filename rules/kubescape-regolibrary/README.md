# kubescape/regolibrary

- Upstream: https://github.com/kubescape/regolibrary
- License: Apache-2.0 (preserved as `LICENSE` alongside these files)
- Commit SHA at import: `ba013fd31b3c44fd1014c8ae7c5184a2f76c58d8`
- Imported files: 353 `.rego` files from the upstream `rules/` tree (test fixtures under each `rules/*/test/` removed)

## What these rules cover

The Kubescape rule library — the policy set used by the CNCF **Kubescape** Kubernetes security posture tool. Rules map to major Kubernetes / cloud-native frameworks:

- **NSA-CISA** Kubernetes hardening guidance
- **MITRE ATT&CK for Containers**
- **CIS Kubernetes Benchmark** (v1.23, v1.24)
- **CIS EKS Benchmark**, **CIS AKS Benchmark**, **CIS GKE Benchmark**
- **ArmoBest**, **DevOpsBest**, **SOC2**
- **Workload Scan** (image-level vulnerability posture)

Typical checks include:

- Privileged containers / privilege escalation / capabilities / host namespace use
- ServiceAccount automounting, cluster-admin role bindings, RBAC least-privilege
- Network policies, ingress controller hardening
- Secret management and anti-pattern scanning (secrets in env vars, hostPath mounts)
- API server & kubelet flag hardening, audit logging
- Resource limits, liveness/readiness probes, image pull policy
- EKS/AKS/GKE-specific control-plane and node config checks

## Layout

Each rule lives in its own subdirectory, with:

```
rules/
└── <rule-name>/
    ├── raw.rego             ← primary rule logic
    ├── filter.rego          ← resource filter
    └── rule.metadata.json   ← metadata (severity, framework mapping, description)
```

Kubescape loads these by walking the directory and pairing `raw.rego` with its metadata.

## Input-schema compatibility

**These rules DO NOT run directly under Vulnetix.** The `package armo_builtins` rules expect `input` to be an **array of Kubernetes resource objects** pre-fetched by the Kubescape engine (each annotated with `relatedObjects` for RBAC, pod-owner resolution, etc). Example shape:

```json
[
  { "kind": "Pod", "apiVersion": "v1", "metadata": { ... }, "spec": { ... } },
  { "kind": "ServiceAccount", "relatedObjects": [ ... ] }
]
```

The Vulnetix CLI passes `{ "file_contents": { ... } }`, so `input[_]` yields nothing and no `deny` is produced.

**To use them with Vulnetix you need one of:**

1. A Rego adapter that parses Kubernetes YAML documents from `input.file_contents` and reshapes them into the armo_builtins input array, resolves RBAC relationships, then re-emits as Vulnetix `findings`.
2. Run **Kubescape** separately (`kubescape scan framework nsa`) and ingest its SARIF/JSON output.

Until an adapter is built, the rules are shipped here as a **policy archive / reference**.

## Metadata

Rule severity and framework mapping live in `rule.metadata.json` next to each `.rego` file — useful for any automation that wants to surface the underlying control IDs or control descriptions.

## Using with the Vulnetix CLI

```bash
vulnetix scan --rule Vulnetix/community-rules --disable-default-rules --dry-run
```

## Attribution

Copyright the ARMO / Kubescape contributors. Licensed under the Apache License, Version 2.0. See `LICENSE`.
