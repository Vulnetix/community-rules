# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_db_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-DB-02",
	"name": "MySQL servers must enable geo-redundant backups",
	"description": "azurerm_mysql_server must set geo_redundant_backup_enabled = true (Basic \"B*\" SKUs exempt).",
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
	"tags": ["terraform", "azure", "mysql", "availability"],
}

findings contains finding if {
	some r in tf.resources("azurerm_mysql_server")
	not _is_geo_redundant(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MySQL server %q has no geo_redundant_backup_enabled = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_is_geo_redundant(block) if tf.bool_attr(block, "geo_redundant_backup_enabled") == true

_is_geo_redundant(block) if startswith(tf.string_attr(block, "sku_name"), "B")
