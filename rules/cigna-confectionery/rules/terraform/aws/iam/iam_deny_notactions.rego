# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_iam_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-IAM-02",
	"name": "IAM policies must not use NotAction",
	"description": "Detects NotAction elements in IAM policy documents — Action should be used instead.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/iam",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam"],
}

_iam_types := {"aws_iam_policy", "aws_iam_group_policy", "aws_iam_role_policy", "aws_iam_user_policy"}

findings contains finding if {
	some t in _iam_types
	some r in tf.resources(t)
	tf.has_not_action(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM policy %q uses NotAction; use Action instead.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
