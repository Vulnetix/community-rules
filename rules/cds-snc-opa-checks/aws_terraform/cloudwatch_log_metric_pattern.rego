# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_cloudwatch_metric_pattern

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-CW-0001",
	"name": "CloudWatch log metric filter pattern must be valid",
	"description": "`aws_cloudwatch_log_metric_filter.pattern` must either be a JSON matcher (`{...}`), a sequence of named fields (`[...]`), or a balanced-quote string of alphanumeric terms.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "cloudwatch"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_cloudwatch_log_metric_filter")
	pattern := tf.string_attr(block, "pattern")
	normalized := replace(pattern, `\\"`, "＂")
	regex.match(`[^[:alnum:],_,\s]`, normalized)
	not regex.match(`(^{.+}$|^\[.+\]$)`, normalized)
	parts := split(normalized, `"`)
	_invalid_pattern(parts)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_cloudwatch_log_metric_filter %q has an invalid filter pattern: %q.", [tf.resource_name(block), pattern]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": pattern,
	}
}

_invalid_pattern(parts) if count(parts) % 2 == 0

_invalid_pattern(parts) if {
	some i
	x := parts[i]
	i % 2 == 0
	regex.match(`[^[:alnum:],_,\s]`, x)
}

_invalid_pattern(parts) if {
	pattern := concat(`"`, parts)
	regex.match(`""`, pattern)
}
