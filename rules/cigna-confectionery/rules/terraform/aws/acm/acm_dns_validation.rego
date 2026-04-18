# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_acm_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-ACM-01",
	"name": "ACM certificates must use DNS validation",
	"description": "aws_acm_certificate resources must not set validation_method to EMAIL.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/acm",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-295"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "acm"],
}

findings contains finding if {
	some r in tf.resources("aws_acm_certificate")
	tf.string_attr(r.block, "validation_method") == "EMAIL"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ACM certificate %q uses EMAIL validation; use DNS instead.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
