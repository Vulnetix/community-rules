# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_vm_01

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-VM-01",
	"name": "VMs must enable automatic updates",
	"description": "Windows VMs must set patch_mode = \"AutomaticByPlatform\" or enable_automatic_updates = true; Linux VMs must set patch_mode = \"AutomaticByPlatform\".",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/virtual-machine",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "virtual-machine", "patching"],
}

findings contains finding if {
	some r in tf.resources("azurerm_windows_virtual_machine")
	not _windows_auto_updated(r.block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Windows VM %q does not enable automatic updates.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

findings contains finding if {
	some r in tf.resources("azurerm_linux_virtual_machine")
	not tf.string_attr(r.block, "patch_mode") == "AutomaticByPlatform"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Linux VM %q does not set patch_mode = AutomaticByPlatform.", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_windows_auto_updated(block) if tf.string_attr(block, "patch_mode") == "AutomaticByPlatform"

_windows_auto_updated(block) if tf.bool_attr(block, "enable_automatic_updates") == true
