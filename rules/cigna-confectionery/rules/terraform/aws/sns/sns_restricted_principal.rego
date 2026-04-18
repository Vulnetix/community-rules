# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_sns_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-SNS-02",
	"name": "SNS topic policies must not grant wildcard Principal without Condition",
	"description": "aws_sns_topic_policy with Effect=Allow and Principal=\"*\" (or AWS:\"*\") must include a Condition.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/sns",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sns", "iam"],
}

findings contains finding if {
	some r in tf.resources("aws_sns_topic_policy")
	tf.has_wildcard_principal_without_condition(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SNS topic policy %q grants wildcard Principal with no Condition.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
