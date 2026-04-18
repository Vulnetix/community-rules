# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_sqs_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-SQS-01",
	"name": "SQS queue policies must not grant wildcard Principal without Condition",
	"description": "aws_sqs_queue_policy with Effect=Allow and Principal=\"*\" (or AWS:\"*\") must include a Condition.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/sqs",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sqs", "iam"],
}

findings contains finding if {
	some r in tf.resources("aws_sqs_queue_policy")
	tf.has_wildcard_principal_without_condition(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQS queue policy %q grants wildcard Principal with no Condition.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
