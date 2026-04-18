# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_vpc_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-VPC-02",
	"name": "Internet Gateways must not be created",
	"description": "aws_internet_gateway is disallowed by policy (internet egress must be controlled).",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/vpc",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "vpc", "network"],
}

findings contains finding if {
	some r in tf.resources("aws_internet_gateway")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Internet Gateway %q is not permitted.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
