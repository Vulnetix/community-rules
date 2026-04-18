# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_sg_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-SG-01",
	"name": "Security group ingress from 0.0.0.0/0 must be limited to port 80 or 443",
	"description": "aws_security_group ingress blocks opening to 0.0.0.0/0 must use port 80 or 443 only.",
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
	_is_bad(ing)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security group %q has ingress from 0.0.0.0/0 on a port other than 80/443.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_bad(block) if {
	_opens_zero_cidr(block)
	not _whitelisted(block)
}

_opens_zero_cidr(block) if {
	vals := tf.string_list_attr(block, "cidr_blocks")
	some v in vals
	v == "0.0.0.0/0"
}

_whitelisted(block) if {
	f := tf.number_attr(block, "from_port")
	t := tf.number_attr(block, "to_port")
	f == t
	_allowed_port(f)
}

_allowed_port(80)
_allowed_port(443)
