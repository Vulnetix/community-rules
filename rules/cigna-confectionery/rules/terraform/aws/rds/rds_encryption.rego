# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_rds_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-RDS-02",
	"name": "RDS instances and clusters must encrypt storage with a KMS CMK",
	"description": "aws_db_instance and aws_rds_cluster must set storage_encrypted = true and reference a kms_key_id.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/rds",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds", "encryption"],
}

_types := {"aws_db_instance", "aws_rds_cluster"}

findings contains finding if {
	some t in _types
	some r in tf.resources(t)
	not _encrypted_with_cmk(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS resource %q is missing storage_encrypted or kms_key_id.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_encrypted_with_cmk(block) if {
	tf.bool_attr(block, "storage_encrypted") == true
	tf.has_key(block, "kms_key_id")
}
