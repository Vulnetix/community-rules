# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_container_trailing_comma

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-ECS-0002",
	"name": "ECS container_definitions must not contain trailing commas",
	"description": "Trailing commas in `aws_ecs_task_definition.container_definitions` break JSON parsing at deploy time.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ecs"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_ecs_task_definition")
	regex.match(`}\s*,+\s*]|]\s*,+\s*}|}\s*,+\s*}|}\s*,+\s*\z|]\s*,+\s*\z|"\s*,+\s*]|"\s*,+\s*}|"\s*,+\s*\z`, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ecs_task_definition %q container_definitions contains a trailing comma.", [tf.resource_name(block)]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": tf.resource_name(block),
	}
}
