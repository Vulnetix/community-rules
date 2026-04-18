# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_cloudfront_error_path

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-CF-0001",
	"name": "CloudFront custom_error_response paths must start with '/'",
	"description": "In `aws_cloudfront_distribution.custom_error_response`, `response_page_path` must start with `/`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudfront_distribution#response_page_path",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "cloudfront"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_cloudfront_distribution")
	matches := regex.find_n(`(?m)response_page_path\s*=\s*"([^"]*)"`, block, -1)
	some m in matches
	parts := regex.find_n(`"([^"]*)"`, m, 1)
	count(parts) > 0
	value := trim(parts[0], `"`)
	not startswith(value, "/")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront response_page_path %q must start with '/'.", [value]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": m,
	}
}
