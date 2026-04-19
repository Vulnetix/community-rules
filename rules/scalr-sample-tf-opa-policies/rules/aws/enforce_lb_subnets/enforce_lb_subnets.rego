# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_lb_subnets

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-AWS-0007",
	"name": "Load balancers must pin subnets to an allow-listed set",
	"description": "`aws_elb` and `aws_lb` resources must only reference subnet IDs listed in `_allowed_subnets`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "lb", "vpc"],
}

_allowed_subnets := {
	"subnet-019c416174b079502",
	"subnet-04dbded374ed11690",
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some t in ["aws_elb", "aws_lb"]
	some block in tf.resource_blocks(content, t)
	subnets := tf.string_list_attr(block, "subnets")
	some sid in subnets
	not _allowed_subnets[sid]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q uses subnet %q which is not in the allow-list.", [t, tf.resource_name(block), sid]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sid,
	}
}
