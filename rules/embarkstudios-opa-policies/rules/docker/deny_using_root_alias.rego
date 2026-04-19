# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_docker_root_alias

import rego.v1

import data.vulnetix.embark.docker

metadata := {
	"id": "EMBARK-DOCKER-02",
	"name": "Dockerfile USER must not alias root",
	"description": "DOCKER_02: USER must not be set to root, toor, or 0.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/DOCKER_02",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "container",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "security", "least-privilege"],
}

_root_aliases := {"root", "toor", "0"}

findings contains finding if {
	some path, content in input.file_contents
	docker.is_dockerfile_path(path)
	some user in docker.users(content)
	name := split(user, ":")[0]
	lower(name) in _root_aliases
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("USER %q resolves to root.", [user]),
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("USER %s", [user]),
	}
}
