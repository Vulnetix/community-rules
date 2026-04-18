# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_enforce_gcs_private

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-GCP-0001",
	"name": "GCS buckets must not be publicly exposed",
	"description": "`google_storage_bucket_access_control.entity = \"Public\"` and `google_storage_bucket_acl.predefined_acl` in {publicRead, publicReadWrite} expose bucket contents publicly.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket_acl",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [284, 732],
	"capec": [],
	"attack_technique": ["T1530"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["gcp", "gcs", "public-access"],
}

_bad_acls := {"publicRead", "publicReadWrite"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "google_storage_bucket_access_control")
	entity := tf.string_attr(block, "entity")
	entity == "Public"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_storage_bucket_access_control %q grants Public entity access.", [tf.resource_name(block)]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": tf.resource_name(block),
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "google_storage_bucket_acl")
	acl := tf.string_attr(block, "predefined_acl")
	_bad_acls[acl]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_storage_bucket_acl %q uses predefined_acl %q.", [tf.resource_name(block), acl]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": acl,
	}
}
