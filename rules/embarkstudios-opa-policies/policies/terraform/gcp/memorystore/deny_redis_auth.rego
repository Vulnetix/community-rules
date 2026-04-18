# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_49

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-49",
	"name": "Memorystore Redis instance must enable AUTH",
	"description": "TF_GCP_49: google_redis_instance must set auth_enabled = true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_49",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-306"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "redis", "authentication"],
}

findings contains finding if {
	some r in tf.resources("google_redis_instance")
	tf.is_not_true(r.block, "auth_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Redis instance %q does not enable AUTH.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
