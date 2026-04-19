# Adapted from https://github.com/iamleot/conftest-policies
# Original License: BSD-2-Clause (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.iamleot_venom_timeout

import rego.v1

metadata := {
	"id": "IAMLEOT-VENOM-TO-001",
	"name": "Venom test step should declare timeout",
	"description": "Venom test steps without a `timeout` can hang indefinitely. Set `timeout` explicitly (use 0 to opt-out).",
	"help_uri": "https://cwe.mitre.org/data/definitions/400.html",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [400],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["venom", "testing", "timeout"],
}

_looks_like_venom(content) if regex.match(`(?m)^testcases\s*:`, content)

_line_of(content, offset) := line if {
	offset >= 0
	prefix := substring(content, 0, offset)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

# Steps section present but no timeout: key anywhere in file
findings contains finding if {
	some path, content in input.file_contents
	regex.match(`(?i)\.ya?ml$`, path)
	_looks_like_venom(content)
	regex.match(`(?m)^\s*steps\s*:`, content)
	not regex.match(`(?m)^\s*timeout\s*:`, content)
	finding := {
		"rule_id": metadata.id,
		"message": "Venom test defines steps but declares no `timeout`; steps may hang indefinitely.",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": "",
	}
}

# Zero timeout = infinite wait
findings contains finding if {
	some path, content in input.file_contents
	regex.match(`(?i)\.ya?ml$`, path)
	_looks_like_venom(content)
	matches := regex.find_n(`(?m)^\s*timeout\s*:\s*0\s*$`, content, -1)
	some match in matches
	offset := indexof(content, match)
	finding := {
		"rule_id": metadata.id,
		"message": "Venom step has `timeout: 0` — effectively infinite; verify this is intentional.",
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": _line_of(content, offset),
		"snippet": trim_space(match),
	}
}
