# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_container_name_with_spaces

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-ECS-0001",
	"name": "ECS container_definitions names must not contain whitespace",
	"description": "`aws_ecs_task_definition.container_definitions` (JSON) must not declare a container `name` containing whitespace.",
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
	matches := regex.find_n(`"name"\s*:\s*"[^"]*\s+[^"]*"`, block, -1)
	some m in matches
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_ecs_task_definition %q has a container name with whitespace: %s.", [tf.resource_name(block), m]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": m,
	}
}
