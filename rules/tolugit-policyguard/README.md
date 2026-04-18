# ToluGIT/policyguard

- Upstream: https://github.com/ToluGIT/policyguard
- License: MIT (preserved as `LICENSE`)
- Commit SHA at import: `deef0c1a6d68e0a9964ba6565af4f634a41c4b69`
- Imported files: 15 `.rego` files from upstream `policies/aws/`

## What these rules cover

IaC security rules for **AWS Terraform** covering 15 services: ALB/ELB, API Gateway, CloudTrail, DynamoDB, EC2, ECR, IAM, KMS, Lambda, RDS, S3 (encryption + public access), SNS, SQS, VPC. Each violation carries a structured object with `id`, `policy_id`, `severity`, `message`, `details`, and `remediation` fields.

Example checks include ALB HTTPS listeners, API Gateway authorizer required, CloudTrail multi-region + encryption, IAM wildcard policies, KMS key rotation, Lambda environment variable encryption, RDS encryption + backup retention, S3 public-access block + bucket encryption, SG 0.0.0.0/0 ingress, VPC flow logs.

## Layout

```
tolugit-policyguard/
└── policies/
    └── aws/
        └── <service>_security.rego
```

## Input-schema compatibility

Operates on a **parsed Terraform resource** at `input.resource` (PolicyGuard's CLI parses local `.tf` files into this shape). Purely local; no API calls.

Under Vulnetix CLI (`input.file_contents`), rules load but need an adapter to HCL-parse `input.file_contents[path]` and iterate resources per rule.

## Using with the Vulnetix CLI

```bash
# Loads cleanly under Vulnetix; needs adapter to emit findings.
vulnetix scan --rule Vulnetix/community-rules

# Direct use via the upstream policyguard CLI against .tf files:
policyguard scan --path ./terraform --policies rules/tolugit-policyguard/policies/
```

## Attribution

Copyright the PolicyGuard contributors. Licensed under the MIT License. See `LICENSE`.
