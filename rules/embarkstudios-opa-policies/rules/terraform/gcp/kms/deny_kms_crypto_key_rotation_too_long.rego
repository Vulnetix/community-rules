# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_35

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-35",
	"name": "KMS crypto key rotation period must be ≤ 90 days",
	"description": "TF_GCP_35: google_kms_crypto_key must set rotation_period within 90 days (7776000 seconds).",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_35",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-310"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "kms", "key-rotation"],
}

findings contains finding if {
	some r in tf.resources("google_kms_crypto_key")
	not tf.has_key(r.block, "rotation_period")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS crypto key %q has no rotation_period.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("google_kms_crypto_key")
	period := tf.string_attr(r.block, "rotation_period")
	seconds := to_number(trim_right(period, "s"))
	seconds > 7776000
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS crypto key %q rotation_period %q exceeds 90 days.", [r.name, period]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("rotation_period=%s", [period]),
	}
}
