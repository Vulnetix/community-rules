# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_cog_03

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-COG-03",
	"name": "Cognitive Services must disable public network access",
	"description": "azurerm_cognitive_account must set public_network_access_enabled = false.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/cognitive-services",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "cognitive-services", "network"],
}

findings contains finding if {
	some r in tf.resources("azurerm_cognitive_account")
	tf.is_not_false(r.block, "public_network_access_enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cognitive account %q does not set public_network_access_enabled = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
