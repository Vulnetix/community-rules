# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_01

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-01",
	"name": "GCS bucket must enable uniform bucket-level access",
	"description": "TF_GCP_01: google_storage_bucket must set uniform_bucket_level_access = true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_01",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gcs", "hardening"],
}

findings contains finding if {
	some r in tf.resources("google_storage_bucket")
	tf.is_not_true(r.block, "uniform_bucket_level_access")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GCS bucket %q does not enable uniform bucket-level access.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
