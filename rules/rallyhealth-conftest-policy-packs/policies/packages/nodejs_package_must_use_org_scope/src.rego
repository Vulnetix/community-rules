# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.rally_nodejs_org_scope

import rego.v1

import data.vulnetix.rallyhealth.packages_utils
import data.vulnetix.rallyhealth.util

metadata := {
	"id": "PKGSEC-0001",
	"name": "NPM packages must be published under an approved org scope",
	"description": "`package.json` `name` must start with `@<approved-scope>/` to defend against typosquatting (fork and tailor `_approved_org_scopes`).",
	"help_uri": "https://docs.npmjs.com/cli/v7/using-npm/scope",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "sca",
	"cwe": [1357],
	"capec": [],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["nodejs", "package.json", "supply-chain"],
}

_approved_org_scopes := [
	"myorg",
	"myorg-private",
]

findings contains finding if {
	some path, content in input.file_contents
	packages_utils.is_package_json(path)
	pkg := packages_utils.parse_pkg(content)
	name := pkg.name
	not startswith(name, "@")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Package %q is not wrapped under an organization scope (e.g. `@orgscope/mypackage`). Approved scopes: %v.", [name, _approved_org_scopes]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": name,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	packages_utils.is_package_json(path)
	pkg := packages_utils.parse_pkg(content)
	name := pkg.name
	startswith(name, "@")
	org := substring(name, 1, indexof(name, "/"))
	not util.item_startswith_in_list(org, _approved_org_scopes)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Package %q does not use an approved organization scope. Approved scopes: %v.", [name, _approved_org_scopes]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": name,
	}
}
