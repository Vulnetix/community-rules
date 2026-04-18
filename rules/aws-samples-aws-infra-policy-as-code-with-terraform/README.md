# aws-samples/aws-infra-policy-as-code-with-terraform

- Upstream: https://github.com/aws-samples/aws-infra-policy-as-code-with-terraform
- License: Apache-2.0 (preserved as `LICENSE`; `NOTICE` preserved if present)
- Commit SHA at import: `cffa57e515d54dec65acba1d88ef0facd160c49b`
- Imported files: 93 `.rego` files (test rules `*.test.rego` removed)

## What these rules cover

AWS-authored preventive security controls for AWS infrastructure, expressed against Terraform plan JSON. Covers mandatory (`-m-`) and recommended (`-r-`) controls for many AWS services:

- ACM (cert tagging)
- API Gateway (logging, auth, TLS, WAF, usage plans)
- CloudTrail / CloudWatch (log encryption, retention, metric filters)
- DataSync, DynamoDB, EBS, EC2 (encryption, public access, IMDSv2, SG rules)
- ECR / ECS / EKS (image scanning, cluster logging, public endpoints)
- ElastiCache, ELB / ALB / NLB, EMR, Glue, KMS, Lambda
- RDS / Aurora / DocumentDB / DynamoDB encryption, backup, public access
- S3 (block public access, encryption, logging, versioning, TLS-only bucket policy)
- SNS / SQS / SSM / StepFunctions / WAF

## Layout

```
aws-samples-aws-infra-policy-as-code-with-terraform/
├── policy-as-code/
│   └── OPA/
│       ├── policy/
│       │   └── aws/
│       │       ├── <service>/
│       │       │   └── aws-<service>-m|r-<N>.rego
│       │       └── aws.utils.rego
│       └── ...
├── LICENSE
├── NOTICE
└── README.md
```

## Input-schema compatibility

Operates on **local Terraform plan JSON** produced by:

```bash
terraform plan -out plan.out
terraform show -json plan.out > plan.json
opa eval --input plan.json --data policy/ 'data.aws.<service>.<ruleid>.deny'
```

Rules read `input.resource_changes[_]` — a standard Terraform plan shape. That file is local, so these rules fit the "local files only" bar.

Under the Vulnetix CLI (`input.file_contents` schema), these rules will not fire as written because they expect a single parsed JSON document. An adapter would need to detect a Terraform plan JSON inside `input.file_contents`, unmarshal it, and reassign `input := parsed_plan` before calling the rule body — feasible and purely local.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter or upstream OPA to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via OPA against a Terraform plan:
opa eval --input plan.json --data rules/aws-samples-aws-infra-policy-as-code-with-terraform/policy-as-code/OPA/policy/ 'data'
```

## Attribution

Copyright Amazon.com, Inc. or its affiliates. Licensed under the Apache License, Version 2.0. See `LICENSE` and `NOTICE`.
