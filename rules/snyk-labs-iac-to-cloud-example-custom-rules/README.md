# snyk-labs/iac-to-cloud-example-custom-rules

- Upstream: https://github.com/snyk-labs/iac-to-cloud-example-custom-rules
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `2cfc6ad2be733dffe9bcddf84beab07bcf2cb301`
- Imported files: 8 `.rego` files from `lib/` and `rules/` (tests stripped)

## What these rules cover

Official Snyk Labs examples for the **Snyk IaC→Cloud custom-rules** flow. Rules target Terraform and are designed to also evaluate cloud state under Snyk's IaC-to-Cloud pipeline:

- `APPROVED_AMIS` — EC2 instances must use an AMI from an approved allowlist
- `GITHUB_DEFAULT_BRANCH_DELETION_PROTECTION` — GitHub default branch must be protected from deletion
- `NEW_PASSWORD_POLICY` — IAM account password policy minimum requirements
- `REQUIRED_S3_BUCKET_TAGS` — required tag keys/values on S3 buckets
- `S3_BUCKET_ACL` — S3 ACL must be `private` (post-TF-4 resource form)
- `VPC_FLOW_LOG_EXCEPTION` — VPC flow logs required (with dev-prefix exception)

`lib/` contains `relation_helpers.rego` and `relations.rego` for joining related resources (e.g. `aws_s3_bucket` ↔ `aws_s3_bucket_acl`).

## Layout

```
snyk-labs-iac-to-cloud-example-custom-rules/
├── lib/
│   ├── relation_helpers.rego
│   └── relations.rego
├── rules/
│   └── <RULE_ID>/main.rego
├── LICENSE
└── README.md
```

## Input-schema compatibility

**Ported** to the Vulnetix `input.file_contents` text-scanning shape. The original `snyk.resources()` / `snyk.relates()` joins have been replaced with regex-based Terraform (HCL) block scanning and cross-file reference matching via `lib/relation_helpers.rego`.

## Using with the Vulnetix CLI

```bash
# Loads and emits findings directly under the Vulnetix CLI.
vulnetix scan --rule Vulnetix/community-rules
```

## Attribution

© 2023 Snyk Limited. Licensed under the Apache License, Version 2.0. See `LICENSE`.
