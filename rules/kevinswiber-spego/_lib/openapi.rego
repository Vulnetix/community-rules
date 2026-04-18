# Adapted from https://github.com/kevinswiber/spego
# Shared helpers for the Vulnetix port: detect OpenAPI/Swagger documents in
# input.file_contents and expose a parsed view to the rules.

package vulnetix.spego.openapi

import rego.v1

is_openapi_path(path) if endswith(lower(path), ".yaml")

is_openapi_path(path) if endswith(lower(path), ".yml")

is_openapi_path(path) if endswith(lower(path), ".json")

parse_yaml(content) := doc if {
	doc := yaml.unmarshal(content)
	is_object(doc)
}

parse_json(content) := doc if {
	doc := json.unmarshal(content)
	is_object(doc)
}

parse(path, content) := doc if {
	endswith(lower(path), ".json")
	doc := parse_json(content)
}

parse(path, content) := doc if {
	not endswith(lower(path), ".json")
	doc := parse_yaml(content)
}

# True iff the parsed document looks like an OpenAPI/Swagger spec.
is_spec(doc) if is_string(doc.openapi)

is_spec(doc) if is_string(doc.swagger)

# Set of {path, doc} pairs representing every OpenAPI file detected in input.
specs contains out if {
	some path, content in input.file_contents
	is_openapi_path(path)
	doc := parse(path, content)
	is_spec(doc)
	out := {"path": path, "doc": doc}
}

is_method_valid(method) if {
	methods := {"get", "put", "post", "delete", "options", "head", "patch", "trace", "query"}
	method in methods
}

join_path(parts) := joined if {
	joined := concat("/", [s | some p in parts; s := sprintf("%v", [p])])
}
