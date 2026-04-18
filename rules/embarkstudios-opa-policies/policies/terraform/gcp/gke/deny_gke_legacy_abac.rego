# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_45

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-45",
	"name": "GKE must not enable legacy ABAC",
	"description": "TF_GCP_45: google_container_cluster must set enable_legacy_abac = false (or omit).",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_45",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "gke", "authz"],
}

findings contains finding if {
	some r in tf.resources("google_container_cluster")
	tf.bool_attr(r.block, "enable_legacy_abac") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q enables legacy ABAC.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
