# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_46

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-46",
	"name": "Cloud SQL must enable automated backups",
	"description": "TF_GCP_46: google_sql_database_instance must define a backup_configuration block with enabled = true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_46",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "cloudsql", "backup"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	not _backup_enabled(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cloud SQL instance %q has no backup_configuration or backup is disabled.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_backup_enabled(block) if {
	some sub in tf.sub_blocks(block, "backup_configuration")
	regex.match(`(?m)^\s*enabled\s*=\s*true\b`, sub)
}
