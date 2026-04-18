# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_cf_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-CF-03",
	"name": "CloudFront distributions must configure access logging",
	"description": "aws_cloudfront_distribution must include a logging_config block.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/cloudfront",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudfront", "logging"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudfront_distribution")
	not tf.has_sub_block(r.block, "logging_config")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution %q does not enable logging_config.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
