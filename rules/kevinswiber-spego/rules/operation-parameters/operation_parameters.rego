# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.spego_operation_parameters

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0013",
	"name": "OpenAPI operation parameters must be unique",
	"description": "Spectral `operation-parameters`: parameters must not repeat (name,in) pairs, must not mix body/formData, and must have at most one body parameter.",
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
	some triple in _ops_with_params(spec.doc)
	p := triple[0]
	method := triple[1]
	params := triple[2]
	some i1, p1 in params
	some i2, p2 in params
	i1 < i2
	is_object(p1)
	is_object(p2)
	p1.name == p2.name
	p1.in == p2.in
	is_string(p1.name)
	is_string(p1.in)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paths.%s.%s.parameters[%d] duplicates (name=%q, in=%q).", [p, method, i2, p1.name, p1.in]),
		"artifact_uri": spec.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s %s", [upper(method), p]),
	}
}

findings contains finding if {
	some spec in openapi.specs
	some triple in _ops_with_params(spec.doc)
	p := triple[0]
	method := triple[1]
	params := triple[2]
	body_count := count([x | some x in params; is_object(x); x.in == "body"])
	form_count := count([x | some x in params; is_object(x); x.in == "formData"])
	body_count > 0
	form_count > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paths.%s.%s must not mix in:body and in:formData parameters.", [p, method]),
		"artifact_uri": spec.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s %s", [upper(method), p]),
	}
}

findings contains finding if {
	some spec in openapi.specs
	some triple in _ops_with_params(spec.doc)
	p := triple[0]
	method := triple[1]
	params := triple[2]
	body_count := count([x | some x in params; is_object(x); x.in == "body"])
	body_count > 1
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paths.%s.%s has %d in:body parameters; max 1.", [p, method, body_count]),
		"artifact_uri": spec.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s %s", [upper(method), p]),
	}
}

_ops_with_params(doc) := ops if {
	paths := object.get(doc, "paths", {})
	is_object(paths)
	ops := {[p, method, params] |
		some p, path_item in paths
		is_object(path_item)
		some method, op in path_item
		openapi.is_method_valid(method)
		is_object(op)
		params := op.parameters
		is_array(params)
		count(params) > 1
	}
}
