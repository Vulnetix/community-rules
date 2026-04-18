# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_ebs_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-EBS-01",
	"name": "EBS volumes must be encrypted at rest",
	"description": "aws_ebs_volume must not set encrypted = false.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/ebs",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "ebs", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_ebs_volume")
	tf.bool_attr(r.block, "encrypted") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EBS volume %q is not encrypted at rest.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
