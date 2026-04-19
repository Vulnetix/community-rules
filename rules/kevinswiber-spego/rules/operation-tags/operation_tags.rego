# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_operation_tags

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0017",
	"name": "OpenAPI operations must have tags",
	"description": "Spectral `operation-tags`: every operation must have a non-empty `tags` array.",
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
	tags := object.get(op, "tags", null)
	_invalid(tags)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paths.%s.%s.tags must be a non-empty array.", [p, method]),
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s %s", [upper(method), p]),
	}
}

_invalid(v) if is_null(v)

_invalid(v) if not is_array(v)

_invalid(v) if {
	is_array(v)
	count(v) == 0
}
