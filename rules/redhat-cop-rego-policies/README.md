# redhat-cop/rego-policies

- Upstream: https://github.com/redhat-cop/rego-policies
- License: Apache-2.0 (preserved as `LICENSE` alongside these files)
- Commit SHA at import: `5d0bebae7f6abdb9a40fc2bf445e1f253c19a703`
- Imported files: 60 `.rego` files from the upstream `policy/` tree

## What these rules cover

OpenShift / Kubernetes best-practice and compliance policies curated by the Red Hat Communities of Practice. Checks include:

- Container image policy (no `:latest` tag, trusted registries, known digest pinning)
- Pod security (privileged containers, host networking / PID / IPC, allowPrivilegeEscalation, runAsNonRoot)
- Resource governance (requests/limits set, CPU/memory caps, Java heap sizing)
- Liveness and readiness probes configured
- Common Kubernetes label hygiene (`app.kubernetes.io/...`)
- Namespace must have `NetworkPolicy` and `ResourceQuota`
- PCI-DSS control mapping (via the `ocp.pcidss` subtree)
- CIS Kubernetes Benchmark coverage (via the `ocp.cis` subtree)

Rules are packaged for use with Konstraint + OPA Gatekeeper, but the pure policy logic is in `.rego` files and carries Konstraint `# METADATA` comments with matcher specs.

## Layout

```
redhat-cop-rego-policies/
└── policy/
    ├── combine/          ← multi-object policies (e.g. namespace needs NP)
    ├── lib/              ← shared library (konstraint, kubernetes, openshift, memory)
    └── ocp/
        ├── bestpractices/
        ├── cis/
        ├── pcidss/
        └── ...
```

## Input-schema compatibility

**These rules DO NOT run directly under Vulnetix.** They assume the Gatekeeper / Konstraint `input` shape (a Kubernetes admission review or a flat object whose keys are the resource fields), plus the `data.lib.*` shared libraries.

The Vulnetix CLI passes `input` as `{ "file_contents": { ... } }`, so `openshift.containers` and `konstraint_core.format_with_id` return empty, and no `violation` is produced.

**To use them with Vulnetix you need one of:**

1. **Wrap each policy** in a Vulnetix-compatible rule that parses the YAML manifests under `input.file_contents`, constructs an `openshift`-style object view, calls the upstream `violation[msg]` rule, and emits a Vulnetix `findings` object with the correct metadata.
2. **Run Konstraint / Gatekeeper** separately in the pipeline, then ingest SARIF.

Until an adapter is built, the rules are shipped here as a **policy archive / reference** for the compliance logic and mapped controls.

## Using with the Vulnetix CLI

```bash
vulnetix scan --rule Vulnetix/community-rules --disable-default-rules --dry-run
```

Confirm the `Imported N rules from Vulnetix/community-rules` log line.

## Attribution

Copyright the contributors to `redhat-cop/rego-policies`. Licensed under the Apache License, Version 2.0. See `LICENSE`.
