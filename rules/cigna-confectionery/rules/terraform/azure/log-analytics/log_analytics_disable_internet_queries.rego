# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_la_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-LA-01",
	"name": "Log Analytics Workspaces must disable internet queries",
	"description": "azurerm_log_analytics_workspace must set internet_query_enabled = false.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/log-analytics",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "log-analytics", "network"],
}

findings contains finding if {
	some r in tf.resources("azurerm_log_analytics_workspace")
	tf.is_not_false(r.block, "internet_query_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Log Analytics Workspace %q does not set internet_query_enabled = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
