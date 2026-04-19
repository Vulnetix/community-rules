# Adapted from https://github.com/kevinswiber/spego
# Ported to the Vulnetix Rego input schema (input.file_contents).
#
# Upstream walked the entire parsed OpenAPI tree looking for `title` and
# `description` fields containing `eval(`. Walking the parsed object under
# text scanning is preserved via `walk(spec.doc)`.

package vulnetix.rules.spego_no_eval_in_markdown

import rego.v1

import data.vulnetix.spego.openapi

metadata := {
	"id": "SPEGO-OAS-0022",
	"name": "OpenAPI markdown must not invoke JavaScript eval()",
	"description": "Spectral `no-eval-in-markdown`: title/description fields must not contain `eval(`.",
	"help_uri": "https://github.com/kevinswiber/spego",
	"languages": ["openapi", "yaml", "json"],
	"severity": "high",
	"level": "error",
	"kind": "api",
	"cwe": ["CWE-94"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["openapi", "security", "xss"],
}

findings contains finding if {
	some spec in openapi.specs
	walk(spec.doc, [path, value])
	some key in ["title", "description"]
	v := value[key]
	is_string(v)
	contains(lower(v), "eval(")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%q contains `eval(` in %s.", [openapi.join_path(array.concat(path, [key])), spec.path]),
		"artifact_uri": spec.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": v,
	}
}
