# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_aws_s3_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AWS-S3-02",
	"name": "S3 bucket ACLs must not be public or authenticated-read",
	"description": "aws_s3_bucket acl must not start with public- or authenticated-.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/aws/s3",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "aws", "s3"],
}

findings contains finding if {
	some r in tf.resources("aws_s3_bucket")
	acl := tf.string_attr(r.block, "acl")
	_is_public_acl(acl)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("S3 bucket %q uses public ACL %q.", [r.name, acl]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_public_acl(acl) if startswith(acl, "public-")
_is_public_acl(acl) if startswith(acl, "authenticated-")
