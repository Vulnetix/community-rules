# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_postgres_main_password

import rego.v1

import data.vulnetix.cds_snc.reserved_words
import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-RDS-0001",
	"name": "RDS master_password must meet PostgreSQL constraints",
	"description": "`aws_rds_cluster.master_password` must be at least 8 characters, must not contain `/`, `@`, or `\"`, and must not be a Postgres reserved word.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster#master_password",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [521],
	"capec": [49],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "rds", "postgres"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_rds_cluster")
	pw := tf.string_attr(block, "master_password")
	regex.match(`[/"@]+`, pw)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_rds_cluster %q master_password contains disallowed characters (/ @ \").", [tf.resource_name(block)]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": tf.resource_name(block),
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_rds_cluster")
	pw := tf.string_attr(block, "master_password")
	count(pw) < 8
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_rds_cluster %q master_password must be at least 8 characters.", [tf.resource_name(block)]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": tf.resource_name(block),
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_rds_cluster")
	pw := tf.string_attr(block, "master_password")
	reserved_words.words[upper(pw)]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_rds_cluster %q master_password is a Postgres reserved word.", [tf.resource_name(block)]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": tf.resource_name(block),
	}
}
