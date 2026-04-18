# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_rs_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-RS-01",
	"name": "Redshift clusters must be encrypted at rest",
	"description": "aws_redshift_cluster must not set encrypted = false.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/redshift",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "redshift", "encryption"],
}

findings contains finding if {
	some r in tf.resources("aws_redshift_cluster")
	tf.bool_attr(r.block, "encrypted") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redshift cluster %q is not encrypted at rest.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
