# snigdhasambitak/opa-policies

- Upstream: https://github.com/snigdhasambitak/opa-policies
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `c61a4e2d1089e444e960c3a99e4375a7d5336782`
- Imported files: 3 `.rego` files (root `policy.rego` + `infra-policies/`)

## What these rules cover

A small example Rego rule set for **Terraform plans**:

- `policy.rego` — denies `aws_instance` resource changes whose `iam_instance_profile` is not in an approved allowlist (`my_iam_profile`, etc.)
- `infra-policies/main.rego` + `infra-policies/package.rego` — a tag-enforcement pack that iterates `params.changedResources` and requires mandatory tags (`team`, `service`, `env`) on `aws_instance` resources and restricts `env` to `prd`/`stg`/`dev`

Useful mainly as a compact template for writing new tag/IAM-profile checks.

## Layout

```
snigdhasambitak-opa-policies/
├── policy.rego              ← tfplan.resource_changes iteration
├── infra-policies/
│   ├── main.rego            ← top-level tag check
│   └── package.rego         ← mandatory tag / allowed-env helpers
├── LICENSE
└── README.md
```

## Input-schema compatibility

- `policy.rego` reads `input.tfplan` and `input.tfrun` — a **local Terraform plan JSON** (`terraform show -json plan.out`) wrapped in a Scalr-style run envelope.
- `infra-policies/` reads `input.changedResources[_]` — a **local pre-processed resource list**.

Both inputs are local; no API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter to parse the plan JSON from `input.file_contents[path]` and rebind `input.tfplan` / `input.changedResources` accordingly.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via OPA:
opa eval --input plan.json \
         --data rules/snigdhasambitak-opa-policies/ \
         'data.terraform.deny'
```

## Attribution

Copyright the snigdhasambitak/opa-policies contributors. Licensed under the MIT License. See `LICENSE`.
