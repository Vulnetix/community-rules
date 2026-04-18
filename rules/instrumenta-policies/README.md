# instrumenta/policies

- Upstream: https://github.com/instrumenta/policies
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `9eafe392bbec10f34d0b46fafd16b3e919aae271`
- Imported files: 2 `.rego` files (`kubernetes/security.rego` + `kubernetes/lib/kubernetes.rego`)

## What these rules cover

A compact Kubernetes manifest security policy (Conftest-oriented) checking:

- Images using the `:latest` tag
- Missing container memory / CPU limits
- `CAP_SYS_ADMIN` capability added
- Capabilities not dropped (`drop: all`)
- `privileged: true` containers
- `hostPID` / `hostNetwork` / `hostAliases` usage
- `allowPrivilegeEscalation: true`
- `runAsNonRoot: false` / missing
- Writable root filesystem
- hostPath volume mounts

Works across Deployments, StatefulSets, DaemonSets, Pods and other controller kinds via the shared `kubernetes` helper library.

## Layout

```
instrumenta-policies/
└── kubernetes/
    ├── security.rego
    └── lib/
        └── kubernetes.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

Operates on a **parsed Kubernetes YAML manifest** bound to `input` (Conftest reads each local manifest and evaluates each document). Purely local; no API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter to YAML-parse each manifest from `input.file_contents[path]` and rebind `input` to the parsed document.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via Conftest (upstream path):
conftest test --policy rules/instrumenta-policies/kubernetes/ deployment.yaml
```

## Attribution

Copyright (C) 2020 Gareth Rushgrove. Licensed under the Apache License, Version 2.0. See `LICENSE`.
