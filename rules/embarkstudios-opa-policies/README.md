# EmbarkStudios/opa-policies

- Upstream: https://github.com/EmbarkStudios/opa-policies
- License: dual Apache-2.0 / MIT (both preserved as `LICENSE-APACHE` / `LICENSE-MIT`)
- Commit SHA at import: `c6377cad4660e010dc0bb01bb1a5fcf04efa60be`
- Imported files: `policy/` tree (tests stripped)

## What these rules cover

A compact, opinionated rule set written by Embark Studios for Conftest, covering three local-file targets:

- **Dockerfile** (`policy/docker/`) — deny root user, `:latest` tag, ADD for tarballs, curl|sh bashing, apt without `--no-install-recommends`, missing pinned versions, sudo usage, etc.
- **Kubernetes YAML** (`policy/kubernetes/`) — privileged containers, hostPath mounts, resource limits missing, required labels, banned image registries, required readiness/liveness probes.
- **Terraform HCL** (`policy/terraform/`) — required tags, disallowed resource types, provider versions, required S3 bucket properties.

Each rule ships with a `DOCKER_NN` / `K8S_NN` / `TF_NN` ID and a pattern for declaring **exceptions** via a separate `exception` rule.

## Layout

```
embarkstudios-opa-policies/
└── policy/
    ├── docker/        ← Dockerfile rules
    ├── kubernetes/    ← K8s YAML rules
    ├── terraform/     ← Terraform HCL rules
    ├── lib.rego       ← shared helpers (URL builder, exception lookup)
    └── testing.rego   ← test harness (not a policy)
```

## Input-schema compatibility

Operates on **local files** parsed by Conftest: Dockerfile → instruction list; K8s YAML → parsed resource; Terraform HCL → parsed HCL. Purely local; no API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter to parse each file from `input.file_contents[path]` and rebind `input` appropriately per file type.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via Conftest (upstream path):
conftest test --policy rules/embarkstudios-opa-policies/policy/ Dockerfile
conftest test --policy rules/embarkstudios-opa-policies/policy/ deployment.yaml
conftest test --policy rules/embarkstudios-opa-policies/policy/ main.tf
```

## Attribution

Copyright Embark Studios. Dual-licensed under the Apache License 2.0 and the MIT License. See `LICENSE-APACHE` and `LICENSE-MIT`.
