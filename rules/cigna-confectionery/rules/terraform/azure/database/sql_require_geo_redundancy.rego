# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_db_04

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-DB-04",
	"name": "SQL servers must be part of a geo-redundant failover group",
	"description": "Each azurerm_sql_server must be referenced by an azurerm_sql_failover_group.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/database",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "sql", "availability"],
}

findings contains finding if {
	some r in tf.resources("azurerm_sql_server")
	not _has_failover_group(r.name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL server %q has no azurerm_sql_failover_group referencing it.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_has_failover_group(server_name) if {
	some fg in tf.resources("azurerm_sql_failover_group")
	regex.match(sprintf(`azurerm_sql_server\.%s\b`, [server_name]), fg.block)
}
