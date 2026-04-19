# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.rally_ec2_imdsv2_required

import rego.v1

import data.vulnetix.rallyhealth.util

metadata := {
	"id": "AWSSEC-0002",
	"name": "EC2 instances must require IMDSv2",
	"description": "`aws_instance` resources must set `metadata_options.http_tokens = \"required\"` to mitigate SSRF against the instance metadata service.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [918],
	"capec": [664],
	"attack_technique": ["T1552.005"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ec2", "imdsv2", "ssrf"],
}

findings contains finding if {
	some path, content in input.file_contents
	util.is_tf(path)
	some block in util.resource_blocks(content, "aws_instance")
	not _has_imdsv2_required(block)
	name := util.resource_name(block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_instance %q does not require IMDSv2. Add a metadata_options block with http_tokens = \"required\".", [name]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": name,
	}
}

_has_imdsv2_required(block) if {
	regex.match(`(?s)metadata_options\s*\{[^{}]*http_tokens\s*=\s*"required"`, block)
}
