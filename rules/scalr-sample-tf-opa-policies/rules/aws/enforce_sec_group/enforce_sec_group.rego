# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_sec_group

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-AWS-0011",
	"name": "Resources with vpc_security_group_ids must include a required SG",
	"description": "Any resource declaring a `vpc_security_group_ids = [...]` list must include `_required_sg`.",
	"help_uri": "",
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

_required_sg := "sg-0434611e67ac24e27"

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	blocks := regex.find_n(`(?s)resource\s+"[^"]+"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, content, -1)
	some block in blocks
	regex.match(`(?s)vpc_security_group_ids\s*=\s*\[`, block)
	sgs := tf.string_list_attr(block, "vpc_security_group_ids")
	not tf.array_contains(sgs, _required_sg)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s does not include required security group %q.", [tf.resource_address(block), _required_sg]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": tf.resource_address(block),
	}
}
