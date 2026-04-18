# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_cf_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-CF-02",
	"name": "CloudFront viewer protocol must enforce HTTPS",
	"description": "default_cache_behavior.viewer_protocol_policy must be redirect-to-https or https-only.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/cloudfront",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "cloudfront", "https"],
}

findings contains finding if {
	some r in tf.resources("aws_cloudfront_distribution")
	some sb in tf.sub_blocks(r.block, "default_cache_behavior")
	v := tf.string_attr(sb, "viewer_protocol_policy")
	not _is_https(v)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFront distribution %q permits HTTP traffic (viewer_protocol_policy=%q).", [r.name, v]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_https(v) if v == "redirect-to-https"
_is_https(v) if v == "https-only"
