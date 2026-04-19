# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.scalr_pin_module_version

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-MOD-0001",
	"name": "Module calls must pin versions from the approved map",
	"description": "For each `module \"NAME\" { source = \"...\" }` whose `source` appears in `_pins`, the `version` attribute must equal the pinned value.",
	"help_uri": "",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [1104],
	"capec": [],
	"attack_technique": ["T1195"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "modules", "supply-chain"],
}

_pins := {
	"terraform-aws-modules/rds/aws": "2.5.0",
	"terraform-aws-modules/another-module": "1.0",
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	blocks := regex.find_n(`(?s)module\s+"[^"]+"\s*\{(?:[^{}]|\{[^{}]*\})*?\}`, content, -1)
	some block in blocks
	source := tf.string_attr(block, "source")
	expected := _pins[source]
	version := tf.string_attr(block, "version")
	version != expected
	header := regex.find_n(`module\s+"[^"]+"`, block, 1)
	count(header) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s source=%q version %q does not match pinned %q.", [header[0], source, version, expected]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": header[0],
	}
}
