# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_52

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-52",
	"name": "Cloud SQL Postgres must enable point-in-time recovery",
	"description": "TF_GCP_52: Postgres google_sql_database_instance must set backup_configuration.point_in_time_recovery_enabled = true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_52",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "cloudsql", "postgres", "backup"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	dbver := tf.string_attr(r.block, "database_version")
	contains(dbver, "POSTGRES")
	not _pitr_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Postgres instance %q has no point_in_time_recovery_enabled.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_pitr_enabled(block) if {
	some sub in tf.sub_blocks(block, "backup_configuration")
	regex.match(`(?m)^\s*point_in_time_recovery_enabled\s*=\s*true\b`, sub)
}
