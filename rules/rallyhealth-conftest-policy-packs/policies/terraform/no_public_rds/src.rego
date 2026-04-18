# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.rally_no_public_rds

import rego.v1

import data.vulnetix.rallyhealth.util

metadata := {
	"id": "AWSSEC-0003",
	"name": "RDS instances must not be publicly accessible",
	"description": "`aws_db_instance` must set `publicly_accessible = false` (or omit the attribute entirely).",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#publicly_accessible",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "rds", "public-access"],
}

findings contains finding if {
	some path, content in input.file_contents
	util.is_tf(path)
	some block in util.resource_blocks(content, "aws_db_instance")
	regex.match(`(?m)^\s*publicly_accessible\s*=\s*true\s*$`, block)
	name := util.resource_name(block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_db_instance %q sets publicly_accessible = true; change it to false.", [name]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": name,
	}
}
