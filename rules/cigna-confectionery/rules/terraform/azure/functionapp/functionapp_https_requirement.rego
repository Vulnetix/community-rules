# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_fa_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-FA-01",
	"name": "Function Apps must require HTTPS",
	"description": "azurerm_function_app must set https_only = true.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/functionapp",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "function-app", "https"],
}

findings contains finding if {
	some r in tf.resources("azurerm_function_app")
	tf.is_not_true(r.block, "https_only")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Function App %q does not set https_only = true.", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
