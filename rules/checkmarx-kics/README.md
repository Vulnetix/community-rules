# Checkmarx/kics

- Upstream: https://github.com/Checkmarx/kics
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `a29d6a86bb3633f84a261bc98f948c8b4b1e03ad`
- Imported files: 1828 `.rego` files from `assets/libraries/` (18) and `assets/queries/` (1810); tests and test fixtures stripped.
- **Vulnetix port status:** imported reference only — queries consume KICS's normalized `input.document[i]` model produced by the KICS Go scanner, which parses HCL/YAML/JSON/Dockerfile/OpenAPI/Ansible/etc. into a document graph before Rego evaluation. A faithful port to Vulnetix's `input.file_contents` text-scanning schema requires a KICS document-model adapter that is not currently available. Use the upstream `kics scan` binary and ingest its SARIF/JSON output via Vulnetix until an adapter lands. For Vulnetix-native rules built with this collection's schema, see `rules/cigna-confectionery/` (Terraform), `rules/gbrindisi-dockerfile-security/` (Dockerfile), and `rules/kevinswiber-spego/` (OpenAPI).

## What these rules cover

KICS ("Keeping Infrastructure as Code Secure") is Checkmarx's production IaC scanner. The bundled Rego rules are the largest open-source IaC policy set, covering 17 input types:

| Platform | Rules | Notes |
|---|---:|---|
| Terraform | 763 | Largest set — AWS/Azure/GCP/OCI/Alicloud/DigitalOcean/IBM/Cloudflare and many providers |
| CloudFormation | 284 | YAML + JSON templates |
| Ansible | 226 | Tasks + playbooks, cloud modules |
| OpenAPI | 194 | OAS 2.0 / 3.x spec hygiene and security |
| Kubernetes | 142 | Pod security, network policy, RBAC, resource limits, etc. |
| Dockerfile | 48 | Image hardening, best practices |
| AzureResourceManager | 42 | ARM template security |
| GoogleDeploymentManager | 35 | GCP DM configs |
| DockerCompose | 21 | Compose file hardening |
| Pulumi | 21 | Pulumi YAML |
| Crossplane | 18 | Provider configurations |
| ServerlessFW | 10 | serverless.yml |
| CI/CD | 4 | GitHub Actions, pipeline checks |
| Buildah, gRPC, Knative | 1 each | Smaller platform coverage |

## Layout

```
checkmarx-kics/
└── assets/
    ├── libraries/           # 18 .rego helper libraries, one per platform
    │   ├── terraform.rego
    │   ├── cloudformation.rego
    │   ├── k8s.rego
    │   ├── dockerfile.rego
    │   ├── ansible.rego
    │   ├── openapi.rego
    │   └── …
    └── queries/             # 1810 .rego queries grouped by platform
        ├── terraform/<rule>/query.rego
        ├── cloudFormation/<rule>/query.rego
        ├── k8s/<rule>/query.rego
        └── …
├── LICENSE
└── README.md
```

Each query lives in its own folder and paired with a `metadata.json` upstream (omitted here — the rego itself is the scanning logic; metadata can be re-downloaded if needed).

## Input-schema compatibility

All queries use the `package Cx` convention and read `input.document[i]` — KICS's normalized document model. The KICS Go scanner parses each IaC source file (HCL, YAML, JSON, Dockerfile, etc.) into this shape and feeds OPA at eval time.

- Purely local: no cloud APIs, no cluster state, no HTTP fetches from rule code.
- Library modules live at `data.generic.<platform>` (e.g. `data.generic.dockerfile`, `data.generic.terraform`).

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that parses each source file into the KICS `input.document[i]` shape.

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter required to produce KICS document model from local files.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via KICS:
kics scan -p ./my-iac --queries-path rules/checkmarx-kics/assets/queries --libraries-path rules/checkmarx-kics/assets/libraries
```

## Attribution

Copyright (c) Checkmarx Ltd. Licensed under the Apache License, Version 2.0.
See `LICENSE`.
