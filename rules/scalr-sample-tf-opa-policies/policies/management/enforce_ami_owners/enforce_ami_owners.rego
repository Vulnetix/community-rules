# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_ami_owners

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-MGMT-0002",
	"name": "aws_ami data sources must use approved owners",
	"description": "Every `owners = [...]` value declared on a `data \"aws_ami\"` must appear in `_allowed_owners`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami#owners",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ami", "supply-chain"],
}

_allowed_owners := {"self", "012345678901"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.data_blocks(content, "aws_ami")
	owners := tf.string_list_attr(block, "owners")
	some owner in owners
	not _allowed_owners[owner]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("data.aws_ami %q uses unapproved owner %q.", [tf.resource_name(block), owner]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": owner,
	}
}
