# Adapted from https://github.com/cigna/confectionery
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.cigna_tf_az_vm_02

import rego.v1

import data.vulnetix.cigna.tf

metadata := {
	"id": "CIGNA-TF-AZ-VM-02",
	"name": "VMs must use an approved SKU (size)",
	"description": "Windows/Linux VMs must set size to an approved SKU from the allowlist.",
	"help_uri": "https://github.com/cigna/confectionery/tree/main/rules/terraform/azure/virtual-machine",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "azure", "virtual-machine", "sku"],
}

valid_vm_sizes := {
	"Standard_A1", "Standard_A1_v2", "Standard_A2_v2", "Standard_A2m_v2", "Standard_A4_v2",
	"Standard_A4m_v2", "Standard_A8_v2",
	"Standard_B1ls", "Standard_B1ms", "Standard_B1s", "Standard_B2ms", "Standard_B2s",
	"Standard_B4hms", "Standard_B4ms", "Standard_B8ms", "Standard_B12ms",
	"Standard_D1_v2", "Standard_D2", "Standard_D2_v2", "Standard_D2_v3", "Standard_D2_v4",
	"Standard_D2a_v4", "Standard_D2as_v4", "Standard_D2d_v4", "Standard_D2ds_v4",
	"Standard_D2hs_v3", "Standard_D2s_v3", "Standard_D2s_v4",
	"Standard_D3_v2", "Standard_D4_v2", "Standard_D4_v3", "Standard_D4_v4", "Standard_D4a_v4",
	"Standard_D4as_v4", "Standard_D4d_v4", "Standard_D4ds_v4", "Standard_D4hs_v3",
	"Standard_D4s_v3", "Standard_D4s_v4",
	"Standard_D8_v3", "Standard_D8_v4", "Standard_D8a_v4", "Standard_D8as_v4",
	"Standard_D8d_v4", "Standard_D8ds_v4", "Standard_D8hs_v3", "Standard_D8s_v3", "Standard_D8s_v4",
	"Standard_D11_v2", "Standard_D12_v2",
	"Standard_DC1s_v2", "Standard_DC2s_v2",
	"Standard_DS1_v2", "Standard_DS2_v2", "Standard_DS3_v2", "Standard_DS4_v2",
	"Standard_DS11_v2", "Standard_DS11-1_v2", "Standard_DS12_v2", "Standard_DS12-1_v2",
	"Standard_DS12-2_v2",
	"Standard_E2_v3", "Standard_E2_v4", "Standard_E2a_v4", "Standard_E2as_v4",
	"Standard_E2d_v4", "Standard_E2ds_v4", "Standard_E2s_v4",
	"Standard_E4_v3", "Standard_E4_v4", "Standard_E4-2as_v4", "Standard_E4-2ds_v4",
	"Standard_E4-2s_v4", "Standard_E4a_v4", "Standard_E4d_v4",
	"Standard_E8_v3", "Standard_E8_v4", "Standard_E8-2as_v4", "Standard_E8a_v4", "Standard_E8s_v3",
	"Standard_F1", "Standard_F1s", "Standard_F2", "Standard_F2s", "Standard_F2s_v2",
	"Standard_F4", "Standard_F4s", "Standard_F4s_v2",
	"Standard_F8", "Standard_F8s", "Standard_F8s_v2", "Standard_F16s_v2",
	"Standard_NV4as_v4", "Standard_NV8as_v4",
}

findings contains finding if {
	some r in _all_vms
	size := tf.string_attr(r.block, "size")
	not valid_vm_sizes[size]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM %q uses unapproved size %q.", [r.name, size]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s.%s", [r.type, r.name]),
	}
}

_all_vms contains r if some r in tf.resources("azurerm_windows_virtual_machine")

_all_vms contains r if some r in tf.resources("azurerm_linux_virtual_machine")
