# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_operation_singular_tag

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0014",
	"name": "OpenAPI operation tags should be singular",
	"description": "Spectral `operation-singular-tag`: operations must not carry more than one tag.",
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
	tags := object.get(op, "tags", [])
	is_array(tags)
	count(tags) > 1
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paths.%s.%s carries %d tags; should be 1.", [p, method, count(tags)]),
		"artifact_uri": spec.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s %s", [upper(method), p]),
	}
}
