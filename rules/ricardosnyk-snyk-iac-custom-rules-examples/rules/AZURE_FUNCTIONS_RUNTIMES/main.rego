# Adapted from https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.ricardo_azure_functions_runtimes

import rego.v1

import data.vulnetix.ricardosnyk.relations

metadata := {
	"id": "RICARDO-AZ-FN-001",
	"name": "Azure Functions runtime must be in allowlist",
	"description": "`azurerm_linux_function_app` / `azurerm_windows_function_app` must declare an application stack that is on the allowlist (`node_version=14` or `powershell_core_version=7`). Tailor to your policy.",
	"help_uri": "https://learn.microsoft.com/en-us/azure/azure-functions/functions-versions",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [1104],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["azure", "functions", "runtime", "terraform"],
}

_function_types := {"azurerm_linux_function_app", "azurerm_windows_function_app"}

_approved_patterns := [
	`application_stack\s*\{[^}]*node_version\s*=\s*"14"`,
	`application_stack\s*\{[^}]*powershell_core_version\s*=\s*"7"`,
]

findings contains finding if {
	some path, content in input.file_contents
	relations.is_tf(path)
	some type in _function_types
	some block in relations.resource_blocks(content, type)
	not _has_approved_stack(block)
	offset := indexof(content, block)
	name := relations.resource_name(block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q uses a non-allowlisted application_stack.", [type, name]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": relations.line_of(content, offset),
		"snippet": sprintf("resource %s %q", [type, name]),
	}
}

_has_approved_stack(block) if {
	some pattern in _approved_patterns
	regex.match(pattern, block)
}
