# hackersifu/example_opa_security_policies

- Upstream: https://github.com/hackersifu/example_opa_security_policies
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `d8744fe6cd4a27ffe9f694b079bad6d59d299148`
- Imported files: 4 `.rego` files from upstream `sample-policies/`

## What these rules cover

Compact example/starter policies for securing AWS IaC via OPA:

- `s3-acl-terraform.rego` — denies any `aws_s3_bucket_acl` that is not `private`
- `s3-tag-value-terraform.rego` — requires a specific tag key/value on S3 buckets
- `security-groups-terraform.rego` — denies security groups opening TCP/22 or TCP/3389 to `0.0.0.0/0`
- `security-groups-cloudformation.rego` — CFN variant of the above

Useful primarily as an easy-to-read template for writing new policies.

## Layout

```
hackersifu-example-opa-security-policies/
├── s3-acl-terraform.rego
├── s3-tag-value-terraform.rego
├── security-groups-terraform.rego
├── security-groups-cloudformation.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

- Terraform rules read `input.planned_values.root_module.resources` — a **local Terraform plan JSON** (`terraform show -json plan.out`).
- CloudFormation rule reads `input.Resources[...]` — a **local CloudFormation template** (JSON or YAML parsed to JSON).

Both inputs are local files. Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter to parse each file from `input.file_contents[path]`.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via OPA:
opa eval --input plan.json \
         --data rules/hackersifu-example-opa-security-policies/ \
         'data.opa_policies.allow'
```

## Attribution

Copyright the hackersifu contributors. Licensed under the Apache License, Version 2.0. See `LICENSE`.
