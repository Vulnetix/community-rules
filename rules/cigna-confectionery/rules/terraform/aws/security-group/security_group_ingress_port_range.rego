# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_sg_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-SG-02",
	"name": "Security groups must not allow all ports",
	"description": "aws_security_group ingress must not set protocol = \"-1\" with from_port = 0 and to_port = 0.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/security-group",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "security-group"],
}

findings contains finding if {
	some r in tf.resources("aws_security_group")
	some ing in tf.sub_blocks(r.block, "ingress")
	_all_ports(ing)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security group %q has an ingress rule opening all ports (protocol=-1).", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_all_ports(block) if {
	tf.string_attr(block, "protocol") == "-1"
	tf.number_attr(block, "from_port") == 0
	tf.number_attr(block, "to_port") == 0
}
