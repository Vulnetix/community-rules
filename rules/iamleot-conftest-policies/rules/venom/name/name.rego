# Adapted from https://github.com/iamleot/conftest-policies
# Original License: BSD-2-Clause (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.iamleot_venom_name

import rego.v1

metadata := {
	"id": "IAMLEOT-VENOM-NAME-001",
	"name": "Venom test file/testcase should declare name",
	"description": "Venom test suites, testcases, and steps should declare a `name:` field so reports and variable references resolve unambiguously.",
	"help_uri": "https://github.com/ovh/venom#concepts",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["venom", "testing", "yaml"],
}

_looks_like_venom(content) if {
	regex.match(`(?m)^testcases\s*:`, content)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(lower(path), ".yml")
	_looks_like_venom(content)
	not regex.match(`(?m)^name\s*:`, content)
	finding := {
		"rule_id": metadata.id,
		"message": "Venom test suite should declare a top-level `name:` key.",
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": "",
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(lower(path), ".yaml")
	_looks_like_venom(content)
	not regex.match(`(?m)^name\s*:`, content)
	finding := {
		"rule_id": metadata.id,
		"message": "Venom test suite should declare a top-level `name:` key.",
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": "",
	}
}
