# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_sqs_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-SQS-02",
	"name": "SQS queues must enable server-side encryption",
	"description": "aws_sqs_queue must set kms_master_key_id.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/sqs",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "sqs", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_sqs_queue")
	not tf.has_key(r.block, "kms_master_key_id")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQS queue %q has no kms_master_key_id.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
