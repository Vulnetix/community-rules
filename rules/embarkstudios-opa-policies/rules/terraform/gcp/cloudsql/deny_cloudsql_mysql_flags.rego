# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_tf_gcp_53

import rego.v1

import data.vulnetix.embark.tf

metadata := {
	"id": "EMBARK-TF-GCP-53",
	"name": "Cloud SQL MySQL must set hardening flags",
	"description": "TF_GCP_53: MySQL google_sql_database_instance must set database_flag local_infile=off.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/TF_GCP_53",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "cloudsql", "mysql", "hardening"],
}

findings contains finding if {
	some r in tf.resources("google_sql_database_instance")
	dbver := tf.string_attr(r.block, "database_version")
	contains(dbver, "MYSQL")
	not _has_flag(r.block, "local_infile", "off")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MySQL instance %q is missing database_flag local_infile=off.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_flag(block, flag_name, flag_value) if {
	some sub in tf.sub_blocks(block, "database_flags")
	tf.string_attr(sub, "name") == flag_name
	tf.string_attr(sub, "value") == flag_value
}
