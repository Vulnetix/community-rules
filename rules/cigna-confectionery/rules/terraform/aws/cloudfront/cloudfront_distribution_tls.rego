# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_cf_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-CF-01",
	"name": "CloudFront viewer TLS minimum must be TLSv1.2 or higher",
	"description": "aws_cloudfront_distribution must configure viewer_certificate.minimum_protocol_version to a TLSv1.2 or TLSv1.3 variant.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/cloudfront",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-326"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudfront", "tls"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudfront_distribution")
	not _has_modern_tls(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution %q does not require TLSv1.2 or newer.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_modern_tls(block) if {
	some sb in tf.sub_blocks(block, "viewer_certificate")
	v := tf.string_attr(sb, "minimum_protocol_version")
	regex.match(`TLSv1\.(2|3)`, v)
}
