# Adapted from https://github.com/iamleot/conftest-policies
# Original License: BSD-2-Clause (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.iamleot_dependabot_toplevel

import rego.v1

import data.vulnetix.iamleot.dependabot_utils as utils

metadata := {
	"id": "IAMLEOT-DEP-001",
	"name": "Dependabot config must declare version: 2 and updates",
	"description": "`.github/dependabot.yml` must contain the top-level keys `version: 2` and `updates:`.",
	"help_uri": "https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dependabot", "dependency-management"],
}

findings contains finding if {
	some path, content in input.file_contents
	utils.is_github_dependabot_path(path)
	not regex.match(`(?m)^updates\s*:`, content)
	finding := {
		"rule_id": metadata.id,
		"message": "`dependabot.yml` is missing required top-level key `updates:`.",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": "",
	}
}

findings contains finding if {
	some path, content in input.file_contents
	utils.is_github_dependabot_path(path)
	not regex.match(`(?m)^version\s*:`, content)
	finding := {
		"rule_id": metadata.id,
		"message": "`dependabot.yml` is missing required top-level key `version:`.",
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": "",
	}
}

findings contains finding if {
	some path, content in input.file_contents
	utils.is_github_dependabot_path(path)
	matches := regex.find_n(`(?m)^version\s*:\s*([0-9]+)`, content, 1)
	count(matches) > 0
	version_str := regex.replace(matches[0], `\D`, "")
	version_str != "2"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("`dependabot.yml` should declare `version: 2`, found %q.", [version_str]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": matches[0],
	}
}
