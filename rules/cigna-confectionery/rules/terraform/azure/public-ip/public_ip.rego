# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_pip_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-PIP-01",
	"name": "Public IPs must not be created",
	"description": "azurerm_public_ip is disallowed by policy.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/public-ip",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "public-ip", "network"],
}

findings contains finding if {
	some r in tf.resources("azurerm_public_ip")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Public IP %q is not permitted.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}
