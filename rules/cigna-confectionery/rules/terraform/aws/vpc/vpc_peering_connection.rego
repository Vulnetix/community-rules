# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_vpc_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-VPC-03",
	"name": "VPC Peering Connections must not be created",
	"description": "aws_vpc_peering_connection is disallowed by policy.",
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
	some r in tf.resources("aws_vpc_peering_connection")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VPC Peering Connection %q is not permitted.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
