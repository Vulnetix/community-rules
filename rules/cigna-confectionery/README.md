# Cigna/confectionery

- Upstream: https://github.com/Cigna/confectionery
- License: Apache-2.0 (preserved as `LICENSE`)
- Commit SHA at import: `32ecb2817980b72d0466563e2147cba2107d1bd8`
- Imported files: 114 `.rego` files (`rules/` + `examples/`), including the bundled Fugue Regula lib under `rules/terraform/utilities/regula/lib/`

## What these rules cover

A library of Conftest-invoked rules built on top of the **Fugue Regula** framework to detect misconfigurations in Terraform. Policies use `data.fugue.resources(<type>)` and `fugue.deny_resource_with_message(...)` — the Regula helpers normalize parsed Terraform HCL/JSON into a resource map before evaluation.

Covered platforms:

| Platform | Services |
|---|---|
| **AWS** | ACM, API Gateway, CloudFront, CloudTrail, DynamoDB, EBS, EC2, EKS, ElastiCache, Elasticsearch, IAM, Kinesis, KMS, Lambda, Load Balancer (ALB/ELB), RDS, Redshift, S3, SageMaker, Security Groups, SNS, SQS, VPC |
| **Azure** | Application Gateway, Cognitive Services, Cosmos DB, Database, Databricks, Front Door, Function App, Key Vault, Log Analytics, Logic App, NAT Gateway, Public IP, Redis Cache, Storage Account, Virtual Machine, Web App |

Examples:

- `allowed_aws_regions.rego`, `allowed_aws_resources.rego`
- `allowed_azure_regions.rego`, `allowed_azure_resources.rego`
- `iam_permissive_policy_attachment.rego`
- `minimum_required_tags.rego`

## Layout

```
cigna-confectionery/
├── rules/
│   └── terraform/
│       ├── aws/<service>/<rule>.rego
│       ├── azure/<service>/<rule>.rego
│       ├── regula.rego                 # Conftest integration glue
│       └── utilities/regula/lib/       # Bundled Fugue Regula helper lib
├── examples/
│   ├── rules/*.rego
│   └── code-snippets/
├── LICENSE
└── README.md
```

## Input-schema compatibility

Rules consume the Regula-normalized resource view. Regula's loader parses Terraform HCL/JSON — including Terraform plan JSON when provided — into a canonical shape, then `data.fugue.resources(<type>)` exposes each resource.

- Purely local: no cloud APIs, no runtime `http.send`.
- Uses the same library model as `rules/fugue-regula/` (already in this collection). The bundled lib at `rules/terraform/utilities/regula/lib/` is a vendored copy of Fugue Regula's lib, included so this ruleset is self-contained.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter that parses Terraform into the Regula resource model (same adapter as fugue-regula).

## Using with the Vulnetix CLI

```bash
# Loads cleanly; adapter required to produce Regula resource view from local Terraform files.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via Regula/Conftest (upstream):
regula run --include rules/cigna-confectionery/rules ./my-terraform
# or
conftest test --policy rules/cigna-confectionery/rules ./tfplan.json
```

## Attribution

Copyright Cigna and contributors. Licensed under the Apache License, Version 2.0.
See `LICENSE`.
