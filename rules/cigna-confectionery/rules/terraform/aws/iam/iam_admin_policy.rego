# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_iam_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-IAM-01",
	"name": "IAM policies must not grant full administrative permissions",
	"description": "Detects IAM policy statements with Effect=Allow, Action=* and Resource=*.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/iam",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
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
	tf.has_wildcard_allow_star(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM policy %q grants Action=* with Resource=*.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
