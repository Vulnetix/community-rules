# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_apigw_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-APIGW-02",
	"name": "API Gateway stages must enable access logging",
	"description": "aws_api_gateway_stage must include an access_log_settings block so requests are logged.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/api-gw",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "apigw", "logging"],
}

findings contains finding if {
	some r in tf.resources("aws_api_gateway_stage")
	not tf.has_sub_block(r.block, "access_log_settings")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("API Gateway stage %q does not configure access_log_settings.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
