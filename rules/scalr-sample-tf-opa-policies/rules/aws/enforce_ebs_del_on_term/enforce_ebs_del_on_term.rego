# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_ebs_delete_on_termination

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-AWS-0003",
	"name": "EBS volumes attached to EC2 instances must delete on termination",
	"description": "Any `root_block_device`/`ebs_block_device` sub-block on an `aws_instance` must not set `delete_on_termination = false`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#delete_on_termination",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ec2", "ebs"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_instance")
	some kind in ["root_block_device", "ebs_block_device"]
	subs := tf.sub_blocks(block, kind)
	some sub in subs
	regex.match(`(?m)delete_on_termination\s*=\s*false`, sub)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_instance %q %s has delete_on_termination = false.", [tf.resource_name(block), kind]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": sub,
	}
}
