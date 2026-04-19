# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_operation_success_response

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0015",
	"name": "OpenAPI operations must have a success response",
	"description": "Spectral `operation-success-response`: each operation must expose at least one 2xx or 3xx response.",
	"help_uri": "https://github.com/kevinswiber/spego",
	"languages": ["openapi", "yaml", "json"],
	"severity": "medium",
	"level": "warning",
	"kind": "api",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["openapi", "governance"],
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
	responses := object.get(op, "responses", {})
	is_object(responses)
	not _has_success(responses)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paths.%s.%s has no 2xx/3xx response.", [p, method]),
		"artifact_uri": spec.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s %s", [upper(method), p]),
	}
}

_has_success(responses) if responses["2xx"]

_has_success(responses) if responses["3xx"]

_has_success(responses) if {
	some code, _ in responses
	n := to_number(code)
	n >= 200
	n < 400
}
