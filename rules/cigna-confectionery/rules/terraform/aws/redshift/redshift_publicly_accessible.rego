# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_rs_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-RS-03",
	"name": "Redshift clusters must not be publicly accessible",
	"description": "aws_redshift_cluster must not set publicly_accessible = true.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/redshift",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "redshift", "network"],
}

findings contains finding if {
	some r in tf.resources("aws_redshift_cluster")
	tf.bool_attr(r.block, "publicly_accessible") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redshift cluster %q is publicly_accessible.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
