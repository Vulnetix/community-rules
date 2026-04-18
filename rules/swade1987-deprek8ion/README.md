# swade1987/deprek8ion

- Upstream: https://github.com/swade1987/deprek8ion
- License: MIT (preserved as `LICENSE` alongside these files)
- Commit SHA at import: `6eb570c287d5cce23507ea453fa2cca3aef41bbc`
- Imported files: 8 `.rego` files from upstream `policies/`

## What these rules cover

Detects use of deprecated Kubernetes API versions (apiVersion + kind combinations) in local YAML manifests. One rule file per Kubernetes version (1.16 – 1.22) plus helper rules for cert-manager and ServiceAccount deprecations. Findings tell you to migrate to the successor `apiVersion`.

## Layout

```
swade1987-deprek8ion/
├── kubernetes-1.16.rego
├── kubernetes-1.17.rego
├── kubernetes-1.18.rego
├── kubernetes-1.19.rego
├── kubernetes-1.20.rego
├── kubernetes-1.22.rego
├── _cert-manager.rego
├── _service-account.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

Operates on **local Kubernetes YAML files**. The rules expect `input` to be a single parsed Kubernetes resource (or a `List` wrapper with `input.items`), which Conftest produces when pointed at a `.yaml` file:

```bash
conftest test --policy policies/ my-deployment.yaml
```

Under Vulnetix CLI (`input.file_contents` schema), these rules will not fire as written because `input.apiVersion` is undefined. They would need a thin adapter that iterates `input.file_contents`, YAML-parses each document, and re-evaluates each rule against the parsed object — feasible because the underlying logic is pure local-file analysis.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via Conftest (upstream-supported path):
conftest test --policy rules/swade1987-deprek8ion/ path/to/manifests/
```

## Attribution

Copyright Steve Wade (swade1987). Licensed under the MIT License. See `LICENSE`.
