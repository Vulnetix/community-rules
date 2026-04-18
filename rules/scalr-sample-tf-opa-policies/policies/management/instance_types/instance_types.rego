# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_instance_types

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-MGMT-0004",
	"name": "VM instance sizes must match per-provider allow-list",
	"description": "AWS `aws_instance.instance_type`, Azure `azurerm_*` `vm_size`, and GCE `google_compute_instance.machine_type` must be in `_allowed_types[provider]`.",
	"help_uri": "",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "governance"],
}

_aws_types := {"t2.nano", "t2.micro"}

_azure_sizes := {"Standard_A0", "Standard_A1"}

_gcp_machines := {"n1-standard-1", "n1-standard-2"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "aws_instance")
	val := tf.string_attr(block, "instance_type")
	not _aws_types[val]
	finding := _type_finding(path, tf.resource_address(block), "instance_type", val)
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some t in ["azurerm_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_linux_virtual_machine"]
	some block in tf.resource_blocks(content, t)
	val := tf.string_attr(block, "vm_size")
	not _azure_sizes[val]
	finding := _type_finding(path, tf.resource_address(block), "vm_size", val)
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.resource_blocks(content, "google_compute_instance")
	val := tf.string_attr(block, "machine_type")
	not _gcp_machines[val]
	finding := _type_finding(path, tf.resource_address(block), "machine_type", val)
}

_type_finding(path, address, key, value) := finding if {
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %s %q is not in the allow-list.", [address, key, value]),
		"artifact_uri": path,
		"severity": "low",
		"level": "warning",
		"start_line": 1,
		"snippet": value,
	}
}
