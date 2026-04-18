# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_iam_04

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-IAM-04",
	"name": "aws_iam_policy_document must not grant wildcard principals",
	"description": "Allow statements whose principals include \"*\" without a condition block are rejected.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/iam",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "iam"],
}

findings contains finding if {
	some r in tf.data_sources("aws_iam_policy_document")
	some stmt in tf.sub_blocks(r.block, "statement")
	tf.string_attr(stmt, "effect") == "Allow"
	_has_wildcard_principal(stmt)
	not tf.has_sub_block(stmt, "condition")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_iam_policy_document %q has an Allow statement with principal \"*\" and no condition.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("data.%s.%s", [r.type, r.name]),
	}
}

_has_wildcard_principal(stmt) if {
	some pb in tf.sub_blocks(stmt, "principals")
	vals := tf.string_list_attr(pb, "identifiers")
	some v in vals
	v == "*"
}
