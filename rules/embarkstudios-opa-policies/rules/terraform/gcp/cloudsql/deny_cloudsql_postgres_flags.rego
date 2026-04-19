# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_54

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-54",
	"name": "Cloud SQL Postgres must set hardening flags",
	"description": "TF_GCP_54: Postgres google_sql_database_instance must set logging database_flags (log_checkpoints, log_connections, log_disconnections, log_lock_waits, log_temp_files, log_min_duration_statement).",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_54",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "cloudsql", "postgres", "logging"],
}

required_flags := {
	"log_checkpoints": "on",
	"log_connections": "on",
	"log_disconnections": "on",
	"log_lock_waits": "on",
	"log_temp_files": "0",
	"log_min_duration_statement": "-1",
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	dbver := tf.string_attr(r.block, "database_version")
	contains(dbver, "POSTGRES")
	missing := [f | some f, v in required_flags; not _has_flag(r.block, f, v)]
	count(missing) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Postgres instance %q is missing flags: %v.", [r.name, missing]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_flag(block, flag_name, flag_value) if {
	some sub in tf.sub_blocks(block, "database_flags")
	tf.string_attr(sub, "name") == flag_name
	tf.string_attr(sub, "value") == flag_value
}
