# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_ct_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-CT-02",
	"name": "CloudTrail must enable log file validation",
	"description": "aws_cloudtrail must set enable_log_file_validation = true (CIS AWS 2.2).",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/cloudtrail",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-354"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudtrail", "cis"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudtrail")
	tf.bool_attr(r.block, "enable_log_file_validation") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudTrail %q has enable_log_file_validation disabled.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
