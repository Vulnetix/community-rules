# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).
#
# Upstream used plan-tree `module_address` to distinguish root-module vs
# module-declared resources. Under text scanning we approximate with a
# simpler rule: if a resource of a protected type appears in *any* file
# alongside a matching `module` call whose source is the approved module,
# we allow it; otherwise we flag the resource.

package vulnetix.rules.scalr_required_modules

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-MOD-0002",
	"name": "Protected resource types must be declared via an approved module",
	"description": "`_required_modules[resource_type] = module_source` — any matching resource block that exists without an approved `module` call sharing the same source triggers a finding.",
	"help_uri": "",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "modules", "governance"],
}

_required_modules := {"aws_db_instance": "terraform-aws-modules/rds/aws"}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some t, expected_source in _required_modules
	some block in tf.resource_blocks(content, t)
	not _approved_module_invoked(content, expected_source)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s must be created via module source %q; no approved module call found.", [tf.resource_address(block), expected_source]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": tf.resource_address(block),
	}
}

_approved_module_invoked(content, expected_source) if {
	blocks := regex.find_n(`(?s)module\s+"[^"]+"\s*\{(?:[^{}]|\{[^{}]*\})*?\}`, content, -1)
	some block in blocks
	tf.string_attr(block, "source") == expected_source
}
