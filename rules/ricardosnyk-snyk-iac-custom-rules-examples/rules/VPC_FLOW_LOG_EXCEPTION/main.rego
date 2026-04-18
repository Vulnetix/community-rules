# Adapted from https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.ricardo_vpc_flow_log

import rego.v1

import data.vulnetix.ricardosnyk.relations

metadata := {
	"id": "RICARDO-VPC-FLOW-001",
	"name": "VPC must have flow logs unless exempted by tag",
	"description": "Each `aws_vpc` must be paired with an `aws_flow_log`, unless the VPC carries tag `name = \"cloudbank-fix\"`.",
	"help_uri": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [778],
	"capec": [],
	"attack_technique": ["T1562.008"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "vpc", "flow-logs"],
}

findings contains finding if {
	some path, content in input.file_contents
	relations.is_tf(path)
	some block in relations.resource_blocks(content, "aws_vpc")
	name := relations.resource_name(block)
	not _is_exempt(block)
	not _has_flow_log(name)
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_vpc %q has no aws_flow_log and no `name=cloudbank-fix` tag exemption.", [name]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": relations.line_of(content, offset),
		"snippet": sprintf("aws_vpc %q", [name]),
	}
}

_is_exempt(block) if regex.match(`(?s)tags\s*=\s*\{[^}]*\bname\s*=\s*"cloudbank-fix"`, block)

_has_flow_log(vpc_name) if {
	some _, content in input.file_contents
	blocks := relations.resource_blocks(content, "aws_flow_log")
	some block in blocks
	regex.match(sprintf(`aws_vpc\.%s\.`, [regex.split(`\.`, vpc_name)[0]]), block)
}
