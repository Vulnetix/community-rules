# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_iam_05

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-IAM-05",
	"name": "IAM policies must list service actions, not service:* wildcards",
	"description": "Detects Action values matching <service>:* in policies that allow on Resource=*.",
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
	tf.has_service_star_action(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM policy %q uses a <service>:* wildcard action.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
