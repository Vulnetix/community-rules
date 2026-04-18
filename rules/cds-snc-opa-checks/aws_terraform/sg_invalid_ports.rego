# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_sg_invalid_ports

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-SG-0001",
	"name": "Security group rules using protocol -1 must set from/to_port = 0",
	"description": "An `aws_security_group` ingress/egress rule with `protocol = \"-1\"` (all protocols) must use `from_port = 0` and `to_port = 0`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "security-group"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_security_group")
	some direction in ["ingress", "egress"]
	subs := tf.sub_blocks(block, direction)
	some sub in subs
	regex.match(`(?m)protocol\s*=\s*"-1"`, sub)
	not regex.match(`(?m)from_port\s*=\s*0\b`, sub)
	finding := _port_finding(path, block, direction, sub)
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_security_group")
	some direction in ["ingress", "egress"]
	subs := tf.sub_blocks(block, direction)
	some sub in subs
	regex.match(`(?m)protocol\s*=\s*"-1"`, sub)
	not regex.match(`(?m)to_port\s*=\s*0\b`, sub)
	finding := _port_finding(path, block, direction, sub)
}

_port_finding(path, block, direction, sub) := finding if {
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_security_group %q has %s rule with protocol=-1 but from/to_port is not 0.", [tf.resource_name(block), direction]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sub,
	}
}
