# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_instance_subnet

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-AWS-0005",
	"name": "EC2 instances must pin subnet_id to an allow-listed private subnet",
	"description": "An `aws_instance` must declare `subnet_id`, and the value must be in `_allowed_subnets`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#subnet_id",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ec2", "vpc"],
}

_allowed_subnets := {
	"subnet-019c416174b079502",
	"subnet-04dbded374ed11690",
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_instance")
	not regex.match(`(?m)^\s*subnet_id\s*=`, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_instance %q does not declare subnet_id.", [tf.resource_name(block)]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": tf.resource_address(block),
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_instance")
	subnet := tf.string_attr(block, "subnet_id")
	not _allowed_subnets[subnet]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_instance %q subnet_id %q is not in the allow-list.", [tf.resource_name(block), subnet]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": subnet,
	}
}
