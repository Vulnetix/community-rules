# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_waf_duplicate_priority

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-WAF-0001",
	"name": "WAFv2 ACL rules must have unique priorities",
	"description": "Within an `aws_wafv2_web_acl`, every `rule { priority = N }` must use a distinct `N`.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "waf"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_wafv2_web_acl")
	priorities := regex.find_n(`(?m)^\s*priority\s*=\s*(\d+)`, block, -1)
	count(priorities) > 0
	values := [v |
		some p in priorities
		caps := regex.find_n(`\d+`, p, 1)
		count(caps) > 0
		v := caps[0]
	]
	count(values) != count({v | some v in values})
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_wafv2_web_acl %q has duplicate rule priorities.", [tf.resource_name(block)]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": tf.resource_name(block),
	}
}
