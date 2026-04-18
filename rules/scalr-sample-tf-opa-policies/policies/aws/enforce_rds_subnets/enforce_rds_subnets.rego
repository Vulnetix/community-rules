# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_rds_subnets

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-AWS-0008",
	"name": "RDS subnet groups must pin subnets to an allow-listed set",
	"description": "`aws_db_subnet_group.subnet_ids` must only reference subnets listed in `_allowed_subnets`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_subnet_group",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "rds", "vpc"],
}

_allowed_subnets := {
	"subnet-019c416174b079502",
	"subnet-04dbded374ed11690",
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_db_subnet_group")
	subnets := tf.string_list_attr(block, "subnet_ids")
	some sid in subnets
	not _allowed_subnets[sid]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_db_subnet_group %q uses subnet %q which is not in the allow-list.", [tf.resource_name(block), sid]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sid,
	}
}
