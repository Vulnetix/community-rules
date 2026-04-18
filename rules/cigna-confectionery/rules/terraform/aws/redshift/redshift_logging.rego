# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_rs_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-RS-02",
	"name": "Redshift clusters must enable audit logging",
	"description": "aws_redshift_cluster must include a logging block.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/redshift",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "redshift", "logging"],
}

findings contains finding if {
	some r in tf.resources("aws_redshift_cluster")
	not tf.has_sub_block(r.block, "logging")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redshift cluster %q does not enable logging.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
