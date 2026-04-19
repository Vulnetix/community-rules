# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Ported to the Vulnetix Rego input schema (input.file_contents).
#
# Upstream made an HTTP call to raw.githubusercontent.com to look up the
# latest LTS Node release. The Vulnetix scanner runs offline, so this port
# hard-codes a minimum LTS floor. Update `_min_lts_major` as Node LTS moves.

package vulnetix.rules.rally_nodejs_recent_version

import rego.v1

import data.vulnetix.rallyhealth.packages_utils

metadata := {
	"id": "PKGSEC-0002",
	"name": "NodeJS projects must pin a recent Node engine",
	"description": "`package.json` must declare an `engines.node` constraint with a minimum version within the last two LTS releases.",
	"help_uri": "https://nodejs.org/en/about/releases/",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "sca",
	"cwe": [1104],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["nodejs", "package.json", "engines"],
}

# Oldest major that is still within two LTS releases of current.
# As of 2026-04 the active LTS is 22, previous supported LTS is 20.
_min_lts_major := 20

findings contains finding if {
	some path, content in input.file_contents
	packages_utils.is_package_json(path)
	pkg := packages_utils.parse_pkg(content)
	not _has_node_engine(pkg)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("package.json declares no engines.node constraint; require Node >= %d.", [_min_lts_major]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": "",
	}
}

findings contains finding if {
	some path, content in input.file_contents
	packages_utils.is_package_json(path)
	pkg := packages_utils.parse_pkg(content)
	_has_node_engine(pkg)
	engine := pkg.engines.node
	_is_unapproved_version(engine)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("engines.node constraint %q allows a Node version older than %d (the current LTS floor).", [engine, _min_lts_major]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": engine,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	packages_utils.is_package_json(path)
	pkg := packages_utils.parse_pkg(content)
	_has_node_engine(pkg)
	engine := pkg.engines.node
	_missing_minimum_constraint(engine)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("engines.node constraint %q does not set a minimum (>=) version; require Node >= %d.", [engine, _min_lts_major]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": engine,
	}
}

_has_node_engine(pkg) if {
	pkg.engines.node
}

_is_unapproved_version(engine_string) if {
	cleaned := _strip_symbols(engine_string)
	parts := split(cleaned, " ")
	some p in parts
	p != ""
	n := to_number(p)
	n < _min_lts_major
}

_missing_minimum_constraint(engine_string) if {
	not contains(engine_string, ">")
}

_strip_symbols(s) := out if {
	out := replace(replace(replace(replace(s, "<", ""), ">", ""), "=", ""), "~", "")
}
