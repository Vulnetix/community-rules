# aquasecurity/trivy-checks

- Upstream: https://github.com/aquasecurity/trivy-checks
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `d7c9302130a9b7e614a5c5d32854f6a08b4bc52e`
- Imported files: 580 `.rego` files from `checks/` and `lib/` (tests and YAML fixtures stripped)
- **Vulnetix port status:** imported reference only — rules consume Trivy's typed `schema["cloud"]` / `schema["dockerfile"]` / `schema["kubernetes"]` resource models produced by Trivy's Go loader, which parses HCL/CFN/YAML/Dockerfile sources before Rego evaluation. A faithful port to Vulnetix's `input.file_contents` text-scanning schema requires a parser adapter that is not currently available. Use the upstream `trivy config` binary and ingest its SARIF/JSON output via Vulnetix until an adapter lands. For Vulnetix-native rules built with this collection's schema, see `rules/gbrindisi-dockerfile-security/` (Dockerfile) and `rules/cigna-confectionery/` (Terraform).

## What these rules cover

Upstream policy set that powers **Trivy** misconfiguration scanning. Coverage:

- **Cloud IaC** (`checks/cloud/`, 366 rules) — AWS, Azure, CloudStack, DigitalOcean, GitHub, Google Cloud, Kubernetes, Nifcloud, OpenStack, Oracle Cloud. Rules target Terraform HCL and CloudFormation (parsed into a normalized `schema["cloud"]` model).
- **Docker** (`checks/docker/`, 28 rules) — Dockerfile best practices: `ADD` vs `COPY`, root user, package pinning, chown restrictions, `--no-cache`, HEALTHCHECK, etc.
- **Kubernetes** (`checks/kubernetes/`, 169 rules) — Pod/container security: capabilities, privileged, hostPath, resource limits, seccomp/AppArmor, RBAC, network policies, PSS-aligned controls.

Every check carries an AVD-style `# METADATA` block with `id`, `long_id`, `severity`, `recommended_action`, and a `schemas` declaration that pins its input shape.

## Layout

```
aquasecurity-trivy-checks/
├── checks/
│   ├── cloud/<provider>/<service>/<rule>.rego
│   ├── docker/<rule>.rego
│   └── kubernetes/<rule>.rego
├── lib/
│   ├── cloud/       # aws_iam, aws_s3, aws_trails, azure_database, google_iam, net, metadata, value, datetime
│   ├── docker/      # docker, cmdutil, path
│   ├── kubernetes/  # kubernetes, security_context, utils
│   └── test/        # shared helpers
├── LICENSE
└── README.md
```

## Input-schema compatibility

Checks use Trivy's schema-typed inputs:

- `schema["cloud"]` — Trivy's internal IaC model (HCL/CloudFormation parsed into provider resources at `input.aws.*`, `input.azure.*`, `input.google.*`, etc.)
- `schema["dockerfile"]` — parsed Dockerfile commands at `input[i].{Cmd,Value,Flags,Stage}`
- `schema["kubernetes"]` — parsed K8s manifest objects

All inputs derive from **local source files**; no network calls, no cluster API reads, no registry fetches. The checks pass the "local files only" filter.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that:

1. Parses each local Terraform/CloudFormation/Dockerfile/K8s YAML from `input.file_contents[path]`.
2. Projects the result into Trivy's `cloud` / `dockerfile` / `kubernetes` schema shape.

Without the adapter the checks will return empty result sets. The `lib/` tree is reusable as-is once the adapter is in place.

## Using with the Vulnetix CLI

```bash
# Loads under Vulnetix; adapter required to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via Trivy:
trivy config --policy rules/aquasecurity-trivy-checks/checks ./terraform
```

## Attribution

Copyright (c) 2024 Aqua Security. Licensed under the MIT License. See `LICENSE`.
