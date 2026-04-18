# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_agw_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-AGW-01",
	"name": "Application Gateway must have an attached WAF policy",
	"description": "azurerm_application_gateway must set firewall_policy_id.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/app-gateway",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "app-gateway", "waf"],
}

findings contains finding if {
	some r in tf.resources("azurerm_application_gateway")
	not tf.has_key(r.block, "firewall_policy_id")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Application Gateway %q has no firewall_policy_id.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
