# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_iam_07

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-IAM-07",
	"name": "IAM users must not be declared in Terraform",
	"description": "Workloads should use roles and identity federation. aws_iam_user resources are rejected.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/iam",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-798"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam"],
}

findings contains finding if {
	some r in tf.resources("aws_iam_user")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_iam_user %q should not be created; use roles and federation.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
