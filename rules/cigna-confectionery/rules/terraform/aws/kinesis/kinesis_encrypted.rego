# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_kin_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-KIN-01",
	"name": "Kinesis streams must be encrypted with a customer-managed KMS key",
	"description": "aws_kinesis_stream must set encryption_type = KMS and kms_key_id must not be empty or alias/aws/kinesis.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/kinesis",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "kinesis", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_kinesis_stream")
	_bad_encryption(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Kinesis stream %q must use a customer-managed KMS key.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_bad_encryption(block) if tf.string_attr(block, "encryption_type") == "NONE"
_bad_encryption(block) if {
	tf.string_attr(block, "encryption_type") == "KMS"
	tf.string_attr(block, "kms_key_id") == "alias/aws/kinesis"
}
_bad_encryption(block) if {
	tf.string_attr(block, "encryption_type") == "KMS"
	not tf.has_key(block, "kms_key_id")
}
