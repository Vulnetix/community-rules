# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_rds_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-RDS-03",
	"name": "RDS DB instances must enable Multi-AZ",
	"description": "aws_db_instance must set multi_az = true unless the engine is Aurora, SQL Server, or DocumentDB.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/rds",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds", "availability"],
}

findings contains finding if {
	some r in tf.resources("aws_db_instance")
	not _is_multi_az(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS instance %q does not enable multi_az.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_multi_az(block) if tf.bool_attr(block, "multi_az") == true
_is_multi_az(block) if startswith(tf.string_attr(block, "engine"), "aurora")
_is_multi_az(block) if startswith(tf.string_attr(block, "engine"), "sqlserver")
_is_multi_az(block) if startswith(tf.string_attr(block, "engine"), "docdb")
