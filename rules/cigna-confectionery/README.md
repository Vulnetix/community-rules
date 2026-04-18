# Cigna/confectionery

- Upstream: https://github.com/Cigna/confectionery
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `32ecb2817980b72d0466563e2147cba2107d1bd8`

## What changed in the port

The upstream ruleset is built on **Fugue Regula**: rules query a parsed HCL/JSON resource view via `data.fugue.resources(<type>)` and emit judgements with `fugue.deny_resource_with_message(...)`.

This port rewrites each rule to the Vulnetix custom SAST schema:

- `package vulnetix.rules.cigna_tf_<cloud>_<service>_<nn>`
- `import rego.v1`
- A `metadata` object (`id`, `name`, `description`, `help_uri`, `languages`, `severity`, `level`, `kind`, `cwe`, `capec`, `attack_technique`, `cvssv4`, `cwss`, `tags`)
- A `findings contains finding if { ... }` set rule that walks `input.file_contents` (map of file path → raw file contents)

A shared helper package at `_lib/tf.rego` (`package vulnetix.cigna.tf`) does regex-based HCL extraction — resource/data blocks, attributes, nested sub-blocks, IAM policy heuristics — so each rule stays small and focused.

## Layout

```
cigna-confectionery/
├── _lib/
│   └── tf.rego                    # shared HCL regex helpers
├── rules/
│   └── terraform/
│       ├── aws/<service>/<rule>.rego    # ported Vulnetix rules
│       └── azure/<service>/<rule>.rego  # ported Vulnetix rules
├── LICENSE
└── README.md
```

Upstream directories `examples/`, `rules/terraform/regula.rego`, `rules/terraform/utilities/` and `rules/terraform/aws/vpc/utilities/` are left in place but are **not** loaded by the ported rules — only `_lib/` and the `*.rego` files inside `rules/terraform/aws/` and `rules/terraform/azure/` are part of the port.

## Rule ID scheme

| Prefix | Scope |
|---|---|
| `CIGNA-TF-AWS-<SVC>-<NN>` | AWS Terraform rules |
| `CIGNA-TF-AZ-<SVC>-<NN>` | Azure Terraform rules |

### AWS coverage

ACM, API Gateway, CloudFront, CloudTrail, DynamoDB, EBS, EC2, EKS, ElastiCache, Elasticsearch, IAM, Kinesis, KMS, Lambda, Load Balancer, RDS, Redshift, S3, SageMaker, Security Group, SNS, SQS, VPC.

### Azure coverage

Application Gateway, Cognitive Services, Cosmos DB, Database (MariaDB / MySQL / PostgreSQL / SQL), Databricks, Front Door, Function App, Key Vault, Log Analytics, Logic App, NAT Gateway, Public IP, Redis Cache, Storage Account, Virtual Machine, Web App.

## Input-schema compatibility

Rules consume `input.file_contents` directly — a flat map `{ "path/to/file.tf": "<raw hcl>" }`. No cloud APIs, no runtime `http.send`, no preprocessor.

Because Terraform is analyzed as text (not a parsed HCL AST), these ports are **best-effort** relative to the upstream Regula-based rules:

- Variable references (`var.foo`), module references, and expressions are not resolved.
- Cross-resource lookups (e.g. VPC → flow_log, SQL server → failover group, Cognitive account → CMK) are name-based: a match on `<type>.<name>.id` in the referring block.
- IAM policy checks use regex heuristics that match heredoc JSON, quoted JSON strings, and `jsonencode({...})` HCL forms — they do not evaluate conditions.
- Hard-coded `start_line: 1` on findings; there is no byte-offset tracking.

Given those trade-offs, false positives and false negatives are possible where the upstream Regula version would be more precise. Use upstream Regula/Conftest directly if you have normalized plan JSON.

## Validating

```bash
cd rules/cigna-confectionery
opa check _lib $(find rules/terraform/aws rules/terraform/azure -name '*.rego' -not -path '*/utilities/*')
```

## Attribution

Copyright Cigna and contributors. Licensed under the Apache License, Version 2.0.
See `LICENSE`.
