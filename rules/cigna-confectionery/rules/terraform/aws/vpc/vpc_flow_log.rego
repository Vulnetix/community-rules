# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_vpc_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-VPC-01",
	"name": "VPCs must have an associated flow log",
	"description": "Every aws_vpc should have a matching aws_flow_log referencing its vpc_id for traffic visibility.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/vpc",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "vpc", "logging"],
}

findings contains finding if {
	some r in tf.resources("aws_vpc")
	not _has_matching_flow_log(r.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VPC %q has no aws_flow_log referencing it.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_matching_flow_log(vpc_name) if {
	some fl in tf.resources("aws_flow_log")
	regex.match(sprintf(`vpc_id\s*=\s*aws_vpc\.%s\.id\b`, [vpc_name]), fl.block)
}
