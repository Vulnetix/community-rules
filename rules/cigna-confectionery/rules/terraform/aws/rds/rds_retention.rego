# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_rds_05

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-RDS-05",
	"name": "RDS backup_retention_period must be at least 7 days",
	"description": "aws_db_instance and aws_rds_cluster must set backup_retention_period >= 7.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/rds",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds", "backup"],
}

_types := {"aws_db_instance", "aws_rds_cluster"}

findings contains finding if {
	some t in _types
	some r in tf.resources(t)
	_retention_too_low(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS resource %q backup_retention_period is less than 7 days.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_retention_too_low(block) if not tf.has_key(block, "backup_retention_period")
_retention_too_low(block) if tf.number_attr(block, "backup_retention_period") < 7
