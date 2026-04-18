# Scalr/sample-tf-opa-policies

- Upstream: https://github.com/Scalr/sample-tf-opa-policies
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `20af36816c6aa8c6e7e96a7dc7dd50ad9dbbc49c`
- Imported files: 31 rule `.rego` files + 1 shared helper (tests stripped)

## What these rules cover

Scalr's sample set of OPA policies for Terraform, spanning AWS, GCP, module
governance, provider allow-lists, and Scalr runtime concerns. The rules fall
into two groups:

| Group | Count | Notes |
|---|---|---|
| HCL-scannable | 22 | Ported to emit Vulnetix findings over `.tf` source |
| Scalr-runtime-only | 9 | Kept as no-op metadata stubs — see below |

HCL-scannable rules cover: resource-type allow-list (SCALR-AWS-0001),
security group CIDR / required SG (SCALR-AWS-0002, SCALR-AWS-0011),
EBS delete-on-termination (SCALR-AWS-0003), IAM instance profiles
(SCALR-AWS-0004), subnet pinning for instances/LBs/RDS (SCALR-AWS-0005/7/8),
KMS key references (SCALR-AWS-0006), S3 ACL + SSE (SCALR-AWS-0009/10),
GCS public ACL (SCALR-GCP-0001), denied provisioners (SCALR-MGMT-0001),
AMI owners + allow-list (SCALR-MGMT-0002/7), variable descriptions
(SCALR-MGMT-0003), instance sizes (SCALR-MGMT-0004), required tags/labels
(SCALR-MGMT-0006), module pinning + module-only resources (SCALR-MOD-0001/2),
cloud location allow-list (SCALR-PLACE-0001), provider blacklist
(SCALR-PROV-0001).

## Layout

```
scalr-sample-tf-opa-policies/
├── policies/
│   ├── _lib/tf.rego            (vulnetix.scalr.tf helper package)
│   ├── aws/**                  (12 rules)
│   ├── cost/**                 (1 no-op stub)
│   ├── external_data/**        (1 no-op stub)
│   ├── gcp/**                  (1 rule)
│   ├── management/**           (11 rules / stubs)
│   ├── modules/**              (2 rules)
│   ├── placement/**            (1 rule)
│   ├── providers/**            (1 rule)
│   └── user/**                 (1 no-op stub)
├── LICENSE
└── README.md
```

## Input-schema compatibility

**Ported** to the Vulnetix `input.file_contents` text-scanning shape. Upstream
rules consumed Terraform plan JSON (`input.tfplan.resource_changes`) or Scalr
runtime metadata (`input.tfrun.*`). Under Vulnetix the scanner never invokes
Terraform or Scalr, so this port replaces plan-tree traversal with regex-based
HCL block scanning over raw `.tf` source.

**No-op rules** — the following are *intentionally non-firing* because they
depend on Scalr's runtime/VCS metadata that has no static analogue:

- `policies/aws/enforce_aws_iam_and_workspace` (workspace name)
- `policies/cost/limit_monthly_cost` (cost_estimate)
- `policies/external_data/random_decision` (http.send demo)
- `policies/management/pull_requests` (VCS pull_request)
- `policies/management/workspace_destroy` (plan actions)
- `policies/management/workspace_environment_type` (workspace env + cost)
- `policies/management/workspace_name` (workspace name)
- `policies/management/workspace_tags` (workspace tags)
- `policies/user/check_user` (run author identity)

Each stub declares metadata so the loader is happy, and carries a note
explaining why it is non-firing under text scanning.

Other limitations of the port (vs. plan-based checks):
- Variable/reference resolution is dropped — attribute checks look only at
  literal values; `data.aws_ami.*` and `data.aws_kms_key.*` references are
  accepted by prefix match.
- `required_modules` approximates the plan's `module_address` check with a
  simpler "is there a module call whose source matches?" check within the
  same file.

## Using with the Vulnetix CLI

```bash
vulnetix scan --rule Vulnetix/community-rules
```

## Attribution

Copyright (c) 2020 Petro Protsakh / Scalr. Licensed under the MIT License. See `LICENSE`.
