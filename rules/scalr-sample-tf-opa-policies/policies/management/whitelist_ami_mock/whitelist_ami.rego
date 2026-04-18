# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_whitelist_ami

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-MGMT-0007",
	"name": "EC2 AMI IDs must be in the approved allow-list",
	"description": "Any literal `ami = \"ami-...\"` on `aws_instance` or `aws_launch_template` must appear in `_allowed_amis`. References to `data.aws_ami.*` are permitted.",
	"help_uri": "",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [1104],
	"capec": [],
	"attack_technique": ["T1195"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ami", "supply-chain"],
}

_allowed_amis := {
	"ami-07d0cf3af28718ef8",
	"ami-0a9b2a20d7dc001e0",
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some t in ["aws_instance", "aws_launch_template", "aws_launch_configuration"]
	some block in tf.resource_blocks(content, t)
	ami := tf.string_attr(block, "ami")
	startswith(ami, "ami-")
	not _allowed_amis[ami]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q uses AMI %q which is not in the allow-list.", [t, tf.resource_name(block), ami]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": ami,
	}
}
