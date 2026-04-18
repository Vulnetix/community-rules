# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_rs_04

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-RS-04",
	"name": "Redshift parameter groups must enforce SSL",
	"description": "aws_redshift_parameter_group must include a parameter block { name = \"require_ssl\", value = \"true\" }.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/redshift",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "redshift", "tls"],
}

findings contains finding if {
	some r in tf.resources("aws_redshift_parameter_group")
	not _require_ssl(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redshift parameter group %q does not set require_ssl = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_require_ssl(block) if {
	some pb in tf.sub_blocks(block, "parameter")
	tf.string_attr(pb, "name") == "require_ssl"
	tf.string_attr(pb, "value") == "true"
}
