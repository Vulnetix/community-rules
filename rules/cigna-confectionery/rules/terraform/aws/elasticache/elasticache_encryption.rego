# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_ec_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-EC-01",
	"name": "ElastiCache replication groups must enable encryption at rest and in transit",
	"description": "aws_elasticache_replication_group must set at_rest_encryption_enabled and transit_encryption_enabled to true.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/elasticache",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "elasticache", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_elasticache_replication_group")
	not _fully_encrypted(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Elasticache replication group %q is missing at-rest or in-transit encryption.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_fully_encrypted(block) if {
	tf.bool_attr(block, "at_rest_encryption_enabled") == true
	tf.bool_attr(block, "transit_encryption_enabled") == true
}
