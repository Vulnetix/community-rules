# hackersifu/example_opa_security_policies

- Upstream: https://github.com/hackersifu/example_opa_security_policies
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `d8744fe6cd4a27ffe9f694b079bad6d59d299148`

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

**Ported** to the Vulnetix `input.file_contents` text-scanning shape. The Terraform rules scan `*.tf` source files (HCL), and the CloudFormation rule scans JSON/YAML template files for `AWS::EC2::SecurityGroup` resources.

## Using with the Vulnetix CLI

```bash
# Loads and emits findings directly under the Vulnetix CLI.
vulnetix scan --rule Vulnetix/community-rules
```

## Attribution

Copyright the hackersifu contributors. Licensed under the Apache License, Version 2.0. See `LICENSE`.
