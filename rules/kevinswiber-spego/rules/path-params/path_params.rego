# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).
#
# The upstream rule bundles several checks. We implement three text-tractable
# checks here:
#
#   1. Duplicate variable name inside the same path template (`/a/{x}/b/{x}`).
#   2. Duplicate path parameter *definition* (same name appearing twice in a
#      single operation's `parameters` list).
#   3. Path template declares a {var} that no `parameters` entry describes.
#
# Full "path collision" detection (normalised path comparison) from the
# upstream is out of scope because it depends on precise param name captures
# and produces a lot of noise when applied by prefix alone.

package vulnetix.rules.spego_path_params

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0021",
	"name": "OpenAPI path parameters must be defined and consistent",
	"description": "Spectral `path-params`: templated path variables must appear exactly once in the path, each be defined, and each definition be unique.",
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

# 1. Duplicate variable names within the same path template.
findings contains finding if {
	some spec in openapi.specs
	paths := object.get(spec.doc, "paths", {})
	is_object(paths)
	some p, _ in paths
	matches := regex.find_n(`\{([^{}]+)\}`, p, -1)
	count(matches) > count({m | some m in matches})
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("path %q declares the same parameter name more than once.", [p]),
		"artifact_uri": spec.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": p,
	}
}

# 2. Duplicate path-param *definitions* in an operation's parameters list.
findings contains finding if {
	some spec in openapi.specs
	paths := object.get(spec.doc, "paths", {})
	is_object(paths)
	some p, path_item in paths
	is_object(path_item)
	some method, op in path_item
	openapi.is_method_valid(method)
	is_object(op)
	params := object.get(op, "parameters", [])
	is_array(params)
	some i1, p1 in params
	some i2, p2 in params
	i1 < i2
	is_object(p1)
	is_object(p2)
	p1.in == "path"
	p2.in == "path"
	is_string(p1.name)
	p1.name == p2.name
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("paths.%s.%s.parameters[%d] duplicates path parameter %q.", [p, method, i2, p1.name]),
		"artifact_uri": spec.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s %s", [upper(method), p]),
	}
}

# 3. Path template variable is not defined at the path-item level nor in any
#    operation's parameters list.
findings contains finding if {
	some spec in openapi.specs
	paths := object.get(spec.doc, "paths", {})
	is_object(paths)
	some p, path_item in paths
	is_object(path_item)
	templates := {trim_prefix(trim_suffix(m, "}"), "{") |
		some m in regex.find_n(`\{[^{}]+\}`, p, -1)
	}
	some needed in templates
	not _defined_anywhere(path_item, needed)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("path %q references {%s} but no parameter defines it.", [p, needed]),
		"artifact_uri": spec.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": p,
	}
}

_defined_anywhere(path_item, name) if {
	params := path_item.parameters
	is_array(params)
	some p in params
	is_object(p)
	p.in == "path"
	p.name == name
}

_defined_anywhere(path_item, name) if {
	some method, op in path_item
	openapi.is_method_valid(method)
	is_object(op)
	params := op.parameters
	is_array(params)
	some p in params
	is_object(p)
	p.in == "path"
	p.name == name
}
