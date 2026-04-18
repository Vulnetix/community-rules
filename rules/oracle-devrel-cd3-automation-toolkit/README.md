# oracle-devrel/cd3-automation-toolkit

- Upstream: https://github.com/oracle-devrel/cd3-automation-toolkit
- License: Universal Permissive License (UPL) 1.0 (preserved as `LICENSE`)
- Commit SHA at import: `007e63050fc3da20253f008c4762fa8f9b0a8dec`
- Imported files: 31 `.rego` files from `cd3_automation_toolkit/common/opa/`

## What these rules cover

OPA policies shipped with Oracle's **CD3 Automation Toolkit** for Oracle Cloud Infrastructure (OCI) Terraform deployments. Policies are grouped by domain:

| Domain | Count | Examples |
|---|---|---|
| Compute | 2 | restrict instance types, secure VM access |
| Identity | 9 | deny IAM admin privilege escalation, MFA enforcement, dynamic groups, tenancy admins access, IAM policy checks |
| Logging_Monitoring | 5 | default tags, bucket write logging, log groups, resource tagging, VCN flow logs |
| Network | 9 | ADB access restrictions, default security list, NSG/SL ingress deny, container/DNS/LB/network-security enforcement, OIC access |
| Risk_score | 1 | score constraint check |
| Storage | 5 | block volumes, deny public bucket, FSS, secure database, object-storage security |

## Layout

```
oracle-devrel-cd3-automation-toolkit/
├── opa/
│   ├── Compute/
│   ├── Identity/
│   ├── Logging_Monitoring/
│   ├── Network/
│   ├── Risk_score/
│   └── Storage/
├── LICENSE
└── README.md
```

## Input-schema compatibility

All rules declare `package terraform` and import `input as tfplan`, reading
`input.resource_changes[_]` — i.e. a **Terraform plan JSON**
(`terraform show -json plan.tfplan`). Several rules also reference
`data.IAM_Admins`, `data.administrators`, or similar external data documents
that must be provided alongside the plan.

Purely local — no cloud API calls from rule code.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that
(a) emits the plan JSON and (b) loads any referenced `data.*` documents.

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter needed to produce plan JSON input and data docs.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via OPA:
terraform show -json plan.tfplan | \
  opa eval -d rules/oracle-devrel-cd3-automation-toolkit/opa/ \
    -d data/iam_admins.json \
    --stdin-input 'data.terraform.deny'
```

## Attribution

Copyright (c) 2024 Oracle and/or its affiliates. Licensed under the Universal
Permissive License (UPL), Version 1.0. See `LICENSE`.
