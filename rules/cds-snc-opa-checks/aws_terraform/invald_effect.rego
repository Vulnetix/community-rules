# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_iam_invalid_effect

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-IAM-0001",
	"name": "IAM policy documents must use a valid Effect value",
	"description": "`aws_iam_policy_document.statement.effect` must be either \"Allow\" or \"Deny\".",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [732],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "iam"],
}

_valid_effects := {"Allow", "Deny"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	blocks := regex.find_n(`(?s)data\s+"aws_iam_policy_document"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, content, -1)
	some block in blocks
	matches := regex.find_n(`(?m)^\s*effect\s*=\s*"([^"]*)"`, block, -1)
	some m in matches
	parts := regex.find_n(`"([^"]*)"`, m, 1)
	count(parts) > 0
	value := trim(parts[0], `"`)
	not _valid_effects[value]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_iam_policy_document has invalid effect %q (must be Allow or Deny).", [value]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": m,
	}
}
