# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_kms_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-KMS-01",
	"name": "KMS keys must have rotation enabled",
	"description": "aws_kms_key must not set enable_key_rotation = false (CIS AWS 2.8).",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/kms",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-320"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "kms", "cis"],
}

findings contains finding if {
	some r in tf.resources("aws_kms_key")
	tf.bool_attr(r.block, "enable_key_rotation") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS key %q has enable_key_rotation=false.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
