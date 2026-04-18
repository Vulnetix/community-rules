# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_47

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-47",
	"name": "Cloud SQL must enable auto disk resize",
	"description": "TF_GCP_47: google_sql_database_instance must not set settings.disk_autoresize = false.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_47",
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
	regex.match(`(?m)^\s*disk_autoresize\s*=\s*false\b`, r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cloud SQL instance %q disables disk_autoresize.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
