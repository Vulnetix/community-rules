# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_postgres_db_name

import rego.v1

import data.vulnetix.cds_snc.reserved_words
import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-RDS-0003",
	"name": "RDS database_name must not be a PostgreSQL reserved word",
	"description": "`aws_rds_cluster.database_name` must not match a Postgres reserved word.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster#database_name",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "rds", "postgres"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_rds_cluster")
	dbname := tf.string_attr(block, "database_name")
	reserved_words.words[upper(dbname)]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_rds_cluster %q database_name %q is a Postgres reserved word.", [tf.resource_name(block), dbname]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": dbname,
	}
}
