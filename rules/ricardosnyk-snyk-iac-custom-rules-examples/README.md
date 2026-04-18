# ricardosnyk/snyk-iac-custom-rules-examples

- Upstream: https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `663d064a5c935c325838a34604e154a2fba2a6b7`
- Imported files: 10 `.rego` files from `lib/` and `rules/` (tests stripped)

## What these rules cover

Example custom rules written for the **Snyk IaC custom-rules SDK**, covering:

- `S3_BUCKET_ACL` — deny non-`private` S3 bucket ACLs (new Terraform resource form)
- `REQUIRED_S3_BUCKET_TAGS` — require mandatory tags on S3 buckets
- `NEW_PASSWORD_POLICY` — AWS IAM account password policy requirements
- `VPC_FLOW_LOG_EXCEPTION` — require VPC flow logs (with `dev`-prefix exception)
- `AZURE_FUNCTIONS_RUNTIMES` — deny deprecated Azure Functions runtimes
- `GCP_FUNCTION_RUNTIME` — deny deprecated GCP Cloud Functions runtimes
- `INSTANCE_RULE` — EC2 instance type allow-list
- `OCI_STORAGE_VERSIONING` — require Oracle Cloud bucket versioning

`lib/` contains a `relations.rego` helper and a `gcp_deprecated_runtimes.rego` data table.

## Layout

```
ricardosnyk-snyk-iac-custom-rules-examples/
├── lib/
│   ├── gcp_deprecated_runtimes.rego
│   └── relations.rego
├── rules/
│   └── <RULE_ID>/main.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

Uses the **Snyk IaC custom-rules SDK**: rules declare `input_type := "tf"` and call `snyk.resources(...)` / `snyk.relates(...)` builtins. These resolve against local Terraform files at scan time via the `snyk iac` CLI — purely local; no API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that (a) HCL-parses each `.tf` file from `input.file_contents[path]`, and (b) shims the `snyk.resources` / `snyk.relates` functions against the parsed resource set. Without the shim, rules return empty result sets.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via the upstream Snyk IaC CLI:
snyk iac test --rules rules/ricardosnyk-snyk-iac-custom-rules-examples/ ./terraform
```

## Attribution

Copyright the snyk-iac-custom-rules-examples contributors. Licensed under the Apache License, Version 2.0. See `LICENSE`.
