# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_rds_04

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-RDS-04",
	"name": "RDS instances must not be publicly accessible",
	"description": "aws_db_instance / aws_rds_cluster_instance must not set publicly_accessible = true.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/rds",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "rds", "network"],
}

_types := {"aws_db_instance", "aws_rds_cluster_instance"}

findings contains finding if {
	some t in _types
	some r in tf.resources(t)
	tf.bool_attr(r.block, "publicly_accessible") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RDS resource %q is publicly_accessible.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
