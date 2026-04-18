# Scalr/sample-tf-opa-policies

- Upstream: https://github.com/Scalr/sample-tf-opa-policies
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `20af36816c6aa8c6e7e96a7dc7dd50ad9dbbc49c`
- Imported files: 31 `.rego` files (tests stripped)

## What these rules cover

Scalr's official sample set of OPA policies for Terraform plan enforcement. 31 rules organized by domain:

| Domain | Count | Examples |
|---|---|---|
| aws | 12 | enforce S3 private ACL / encryption, EBS delete-on-termination, IAM instance profiles, RDS/LB subnet pinning, security group rules, KMS key naming, CIDR enforcement |
| gcp | 1 | enforce private GCS buckets |
| cost | 1 | monthly cost limit |
| management | 11 | denied provisioners, enforce AMI owners, enforce variable descriptions, instance-type allowlist, etc. |
| modules | 2 | private registry enforcement |
| placement | 1 | workspace placement guards |
| providers | 1 | provider restrictions |
| user | 1 | user-level policy examples |
| external_data | 1 | demo using `http.send` / external lookups — flagged below |

## Layout

```
scalr-sample-tf-opa-policies/
├── policies/
│   ├── aws/
│   ├── cost/
│   ├── external_data/
│   ├── gcp/
│   ├── management/
│   ├── modules/
│   ├── placement/
│   ├── providers/
│   └── user/
├── LICENSE
└── README.md
```

## Input-schema compatibility

All policies declare `package terraform` and read `input.tfplan.resource_changes[_]` — i.e. a **Terraform plan JSON** embedded under an `input.tfplan` key (Scalr's run-time wrapper, trivially reproducible offline).

Purely local — no cloud API calls from rule code.

**Caveat:** `external_data/random_decision/` is a demo policy that calls `http.send` to a public API. It is included for completeness but will fail under sandboxed/offline evaluation; consumers should omit it if strict no-network evaluation is required.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that builds a `{"tfplan": <plan-json>}` input from a local plan JSON.

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter needed to wrap plan JSON under "tfplan".
vulnetix scan --rule Vulnetix/community-rules

# Direct use via OPA:
terraform show -json plan.tfplan | jq '{tfplan: .}' | \
  opa eval -d rules/scalr-sample-tf-opa-policies/policies/ \
    --stdin-input 'data.terraform.deny'
```

## Attribution

Copyright (c) 2020 Petro Protsakh / Scalr. Licensed under the MIT License. See `LICENSE`.
