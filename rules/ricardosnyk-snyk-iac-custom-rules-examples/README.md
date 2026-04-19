# ricardosnyk/snyk-iac-custom-rules-examples

- Upstream: https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
- Commit SHA at import: `663d064a5c935c325838a34604e154a2fba2a6b7`

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

**Ported** to the Vulnetix `input.file_contents` text-scanning shape. The `snyk.resources()` / `snyk.relates()` joins have been replaced with regex-based HCL block scanning via `lib/relations.rego`. Each rule emits Vulnetix-format findings directly.

## Using with the Vulnetix CLI

```bash
# Loads and emits findings directly under the Vulnetix CLI.
vulnetix scan --rule Vulnetix/community-rules
```

## Attribution

Copyright the snyk-iac-custom-rules-examples contributors. Licensed under the Apache License, Version 2.0.
