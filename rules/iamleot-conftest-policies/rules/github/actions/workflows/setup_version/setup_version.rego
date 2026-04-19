# Adapted from https://github.com/iamleot/conftest-policies
# Original License: BSD-2-Clause (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.iamleot_gha_setup_version

import rego.v1

import data.vulnetix.iamleot.github_actions_utils as utils

metadata := {
	"id": "IAMLEOT-GHA-VER-001",
	"name": "actions/setup-* version must be quoted string",
	"description": "In `actions/setup-{go,java,node,python}` steps, the `*-version` field must be a quoted string — YAML parses unquoted numerics as floats and truncates trailing zeros (e.g. `1.20` → `1.2`).",
	"help_uri": "https://github.com/actions/setup-go",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["github-actions", "yaml", "versioning"],
}

_line_of(content, offset) := line if {
	offset >= 0
	prefix := substring(content, 0, offset)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

_setup_actions := {
	"setup-go": "go-version",
	"setup-java": "java-version",
	"setup-node": "node-version",
	"setup-python": "python-version",
}

# Detect steps using actions/setup-<lang> followed by an unquoted <lang>-version value
findings contains finding if {
	some path, content in input.file_contents
	utils.is_github_workflow_path(path)
	some action, version_key in _setup_actions
	# find uses: actions/setup-<lang>@... followed by with: <version_key>: <numeric>
	pattern := sprintf(`(?s)uses\s*:\s*actions/%s@[^\n]+\n[^\n]*with\s*:\s*[\s\S]{0,200}?%s\s*:\s*([0-9][0-9.]*)\s*(?:#|$|\n)`, [action, version_key])
	matches := regex.find_n(pattern, content, -1)
	some match in matches
	offset := indexof(content, match)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("`%s` passed to actions/%s should be a quoted string (e.g. \"1.20\") to avoid YAML numeric truncation.", [version_key, action]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": _line_of(content, offset),
		"snippet": sprintf("actions/%s: %s: <unquoted>", [action, version_key]),
	}
}
