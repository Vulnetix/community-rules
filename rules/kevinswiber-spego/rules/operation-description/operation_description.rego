# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_operation_description

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0009",
	"name": "OpenAPI operations must include descriptions",
	"description": "Spectral `operation-description`: every HTTP operation must have a non-empty description.",
	"help_uri": "https://github.com/kevinswiber/spego",
	"languages": ["openapi", "yaml", "json"],
	"severity": "low",
	"level": "note",
	"kind": "api",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["openapi", "documentation"],
}

findings contains finding if {
	some spec in openapi.specs
	paths := object.get(spec.doc, "paths", {})
	is_object(paths)
	some p, path_item in paths
	is_object(path_item)
	some method, op in path_item
	openapi.is_method_valid(method)
	is_object(op)
	desc := object.get(op, "description", null)
	_invalid(desc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paths.%s.%s.description is missing or empty.", [p, method]),
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s %s", [upper(method), p]),
	}
}

_invalid(v) if not is_string(v)

_invalid(v) if v == ""
