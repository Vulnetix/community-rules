# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_48

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-48",
	"name": "Cloud SQL must use REGIONAL availability",
	"description": "TF_GCP_48: google_sql_database_instance must set settings.availability_type = REGIONAL.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_48",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "cloudsql", "reliability"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	_availability_not_regional(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cloud SQL instance %q availability_type is not REGIONAL.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_availability_not_regional(block) if not tf.has_key(block, "availability_type")

_availability_not_regional(block) if {
	v := tf.string_attr(block, "availability_type")
	v != "REGIONAL"
}
