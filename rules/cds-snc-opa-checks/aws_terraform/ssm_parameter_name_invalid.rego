# Adapted from https://github.com/cds-snc/opa_checks
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cds_snc_ssm_parameter_name

import rego.v1

import data.vulnetix.cds_snc.tf

metadata := {
	"id": "CDS-SNC-SSM-0001",
	"name": "SSM parameter names must not start with `aws` or `ssm`",
	"description": "AWS reserves the `aws` and `ssm` prefixes (case-insensitive) on SSM parameter names.",
	"help_uri": "https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-su-create.html",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ssm"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_ssm_parameter")
	name := tf.string_attr(block, "name")
	lname := lower(name)
	startswith(lname, "aws")
	finding := _bad_prefix_finding(path, block, name)
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_ssm_parameter")
	name := tf.string_attr(block, "name")
	lname := lower(name)
	startswith(lname, "ssm")
	finding := _bad_prefix_finding(path, block, name)
}

_bad_prefix_finding(path, block, name) := finding if {
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SSM parameter name %q starts with a reserved prefix (aws/ssm).", [name]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": name,
	}
}
