# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_dbx_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-DBX-01",
	"name": "Databricks premium workspaces must enable customer-managed key encryption",
	"description": "azurerm_databricks_workspace on sku = premium must set customer_managed_key_enabled = true.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/databricks",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "databricks", "encryption"],
}

findings contains finding if {
	some r in tf.resources("azurerm_databricks_workspace")
	tf.string_attr(r.block, "sku") == "premium"
	not tf.bool_attr(r.block, "customer_managed_key_enabled") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Databricks premium workspace %q has no customer_managed_key_enabled = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
