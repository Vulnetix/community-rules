# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_ddb_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-DDB-01",
	"name": "DynamoDB tables must enable server-side encryption",
	"description": "aws_dynamodb_table must declare a server_side_encryption block with enabled = true.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/dynamodb",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "dynamodb", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_dynamodb_table")
	not _sse_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("DynamoDB table %q does not enable server_side_encryption.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_sse_enabled(block) if {
	some sb in tf.sub_blocks(block, "server_side_encryption")
	tf.bool_attr(sb, "enabled") == true
}
