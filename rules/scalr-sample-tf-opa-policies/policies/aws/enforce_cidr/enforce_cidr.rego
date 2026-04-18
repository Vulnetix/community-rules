# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_cidr

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-AWS-0002",
	"name": "Security groups must not permit CIDR 0.0.0.0/0",
	"description": "`aws_security_group` ingress/egress rules and `aws_security_group_rule` resources must not include `0.0.0.0/0` in `cidr_blocks`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "security-group", "public-exposure"],
}

_invalid_cidrs := {"0.0.0.0/0"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_security_group")
	some direction in ["ingress", "egress"]
	subs := tf.sub_blocks(block, direction)
	some sub in subs
	cidrs := tf.string_list_attr(sub, "cidr_blocks")
	some cidr in cidrs
	_invalid_cidrs[cidr]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group %q %s rule allows %s.", [tf.resource_name(block), direction, cidr]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sub,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_security_group_rule")
	cidrs := tf.string_list_attr(block, "cidr_blocks")
	some cidr in cidrs
	_invalid_cidrs[cidr]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group_rule %q allows %s.", [tf.resource_name(block), cidr]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": tf.resource_address(block),
	}
}
