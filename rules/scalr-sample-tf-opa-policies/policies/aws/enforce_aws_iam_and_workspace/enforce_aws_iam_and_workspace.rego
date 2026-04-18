# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# NOTE: Upstream depends on Scalr runtime metadata (input.tfrun.workspace.name)
# and the plan configuration tree (input.tfplan.configuration.provider_config)
# — neither is available under Vulnetix text scanning, so this port declares
# metadata but never emits findings. Retain the file so the loader still sees
# a valid rule and can be re-wired when a Scalr adapter is added.

package vulnetix.rules.scalr_enforce_aws_iam_and_workspace

import rego.v1

metadata := {
	"id": "SCALR-AWS-0012",
	"name": "AWS IAM role must match workspace naming (no-op under text scanning)",
	"description": "Upstream requires Scalr runtime workspace metadata; not applicable to file-scanning mode.",
	"help_uri": "https://github.com/Scalr/sample-tf-opa-policies",
	"languages": ["terraform"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "iam", "scalr-runtime"],
}

findings := set()
