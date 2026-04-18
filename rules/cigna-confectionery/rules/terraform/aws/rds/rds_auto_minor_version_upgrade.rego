# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_rds_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-RDS-01",
	"name": "RDS DB instances must enable auto minor version upgrades",
	"description": "aws_db_instance must set auto_minor_version_upgrade = true.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/rds",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds"],
}

findings contains finding if {
	some r in tf.resources("aws_db_instance")
	tf.is_not_true(r.block, "auto_minor_version_upgrade")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS instance %q does not enable auto_minor_version_upgrade.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
