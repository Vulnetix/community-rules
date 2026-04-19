# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).
#
# The upstream rule was document-local. Under text scanning we retain that:
# uniqueness is checked only among operations in the same OpenAPI document.

package vulnetix.rules.spego_operation_operationid_unique

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0011",
	"name": "OpenAPI operationIds must be unique within a document",
	"description": "Spectral `operation-operationId-unique`: no two operations may share an operationId.",
	"help_uri": "https://github.com/kevinswiber/spego",
	"languages": ["openapi", "yaml", "json"],
	"severity": "high",
	"level": "error",
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
	ids := [op.operationId |
		some _, path_item in paths
		is_object(path_item)
		some method, op in path_item
		openapi.is_method_valid(method)
		is_object(op)
		is_string(op.operationId)
		op.operationId != ""
	]
	some _, path_item in paths
	is_object(path_item)
	some method, op in path_item
	openapi.is_method_valid(method)
	is_object(op)
	is_string(op.operationId)
	op.operationId != ""
	dup := count([x | some x in ids; x == op.operationId])
	dup > 1
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("operationId %q is not unique.", [op.operationId]),
		"artifact_uri": spec.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": op.operationId,
	}
}
