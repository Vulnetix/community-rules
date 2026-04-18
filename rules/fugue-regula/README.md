# fugue/regula

- Upstream: https://github.com/fugue/regula
- License: Apache-2.0 (preserved as `LICENSE` alongside these files)
- Commit SHA at import: `259c10a6a746e3c1eb84857d9f548cca463034af`
- Imported files: 321 `.rego` files from `regula/rego/rules/` and `regula/rego/lib/`, plus `remediation.yaml`
- **Vulnetix port status:** imported reference only — upstream rules traverse Regula's parsed-HCL resource tree (e.g. `bucket.server_side_encryption_configuration[_].rule[_][_].sse_algorithm`). A faithful port to Vulnetix's `input.file_contents` text-scanning schema would require an HCL/CFN/YAML parser callable from Rego (not available) or an external pre-processing step. For Vulnetix-native Terraform rules using the same compliance concepts, see `rules/cigna-confectionery/` (text-scanning port) as the reference implementation.

## What these rules cover

Regula is a static-analysis tool for **infrastructure-as-code**: Terraform (HCL + tfplan JSON), AWS CloudFormation, Azure Resource Manager (ARM) templates, and Kubernetes manifests. The rule set maps to widely-used compliance frameworks including **CIS** benchmarks (AWS Foundations, Azure, GCP, Kubernetes), **PCI-DSS**, **GDPR**, **HIPAA**, **SOC2**, **NIST 800-53**, and **ISO 27001**.

Typical checks include:

- S3 bucket public access, encryption, logging, versioning
- IAM password / MFA / key rotation policies
- Security group / NACL overly-permissive rules (0.0.0.0/0 ingress)
- RDS / Aurora / DocumentDB encryption and backup settings
- EKS / AKS / GKE cluster hardening (network policy, control plane logs, private endpoint)
- Azure storage account / SQL server / Key Vault configuration
- GCP Compute instance / storage bucket / IAM hardening
- CloudTrail / CloudWatch / Azure Monitor logging coverage

## Layout

```
fugue-regula/
├── rules/          ← policy rules, organised by IaC target (arm/ cfn/ k8s/ tf/)
├── lib/            ← shared helper library (data.fugue, data.fugue.regula)
├── remediation.yaml
├── LICENSE
└── README.md
```

## Input-schema compatibility

**These rules DO NOT run directly under Vulnetix.** Regula rules use:

```rego
input_type := "tf"   # or "cfn", "arm", "k8s", "tf_plan"
resources := fugue.resources("aws_s3_bucket")
```

They expect `input` to be a **parsed** IaC resource graph (produced by Regula's Go loader), and the `data.fugue` helper library to be wired up with that input shape.

The Vulnetix CLI passes `input` as:

```json
{ "file_contents": { "<path>": "<raw file text>" } }
```

So when loaded under Vulnetix, Regula rules will compile but `fugue.resources(...)` returns empty and no findings are produced.

**To use these rules with Vulnetix you need one of:**

1. **An adapter rule** that parses Terraform/CloudFormation from `input.file_contents[path]` and constructs a `fugue`-compatible resource view, then wraps the Regula `deny`/`policy` outputs into Vulnetix `findings` objects. (Non-trivial — requires an HCL/YAML parser callable from Rego, or a pre-processing step outside Rego.)
2. **Upstream Regula** (`regula run`) as a separate step in the pipeline, then ingest its SARIF output via Vulnetix upload. This is the supported path today.

Until an adapter lands, these rules are shipped here as a **policy archive / reference** — they are valuable for reading the underlying compliance logic even if they do not fire under the Vulnetix CLI.

## Using with the Vulnetix CLI

```bash
# Load (compiles but will not produce findings — see above)
vulnetix scan --rule Vulnetix/community-rules

# Disable built-ins to confirm rules load cleanly
vulnetix scan \
  --rule Vulnetix/community-rules \
  --disable-default-rules \
  --dry-run
```

Watch for the `Imported N rules from Vulnetix/community-rules` log line to confirm parse success.

## Attribution

Copyright 2020-2022 Fugue, Inc. Licensed under the Apache License, Version 2.0. See `LICENSE`.
