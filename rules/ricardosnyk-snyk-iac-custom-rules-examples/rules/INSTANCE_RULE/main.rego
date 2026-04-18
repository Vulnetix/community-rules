# Adapted from https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.ricardo_no_public_ec2

import rego.v1

import data.vulnetix.ricardosnyk.relations

metadata := {
	"id": "RICARDO-EC2-PUBLIC-001",
	"name": "EC2 instances must not associate public IPs",
	"description": "`aws_instance` must not set `associate_public_ip_address = true`.",
	"help_uri": "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html",
	"languages": ["terraform"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": [284],
	"capec": [],
	"attack_technique": ["T1133"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ec2", "network", "terraform"],
}

findings contains finding if {
	some path, content in input.file_contents
	relations.is_tf(path)
	some block in relations.resource_blocks(content, "aws_instance")
	regex.match(`associate_public_ip_address\s*=\s*true`, block)
	offset := indexof(content, block)
	name := relations.resource_name(block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_instance %q sets associate_public_ip_address = true.", [name]),
		"artifact_uri": path,
		"severity": "critical",
		"level": "error",
		"start_line": relations.line_of(content, offset),
		"snippet": "associate_public_ip_address = true",
	}
}
