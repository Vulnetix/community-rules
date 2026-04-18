# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_postgres_main_username

import rego.v1

import data.vulnetix.cds_snc.reserved_words
import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-RDS-0002",
	"name": "RDS master_username must meet PostgreSQL constraints",
	"description": "`aws_rds_cluster.master_username` must start with a letter, be less than 64 characters, and not be a Postgres reserved word.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster#master_username",
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
	name := tf.string_attr(block, "master_username")
	not regex.match(`^[A-Za-z]+`, name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_rds_cluster %q master_username %q must start with a letter.", [tf.resource_name(block), name]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": name,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_rds_cluster")
	name := tf.string_attr(block, "master_username")
	count(name) >= 64
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_rds_cluster %q master_username is >= 64 characters.", [tf.resource_name(block)]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": name,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_rds_cluster")
	name := tf.string_attr(block, "master_username")
	reserved_words.words[upper(name)]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_rds_cluster %q master_username %q is a Postgres reserved word.", [tf.resource_name(block), name]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": name,
	}
}
