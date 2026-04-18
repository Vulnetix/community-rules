# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_docker_using_add

import rego.v1

import data.vulnetix.embark.docker

metadata := {
	"id": "EMBARK-DOCKER-05",
	"name": "Dockerfile must prefer COPY over ADD",
	"description": "DOCKER_05: ADD is discouraged; COPY is safer for non-URL local files.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/DOCKER_05",
	"languages": ["dockerfile"],
	"severity": "low",
	"level": "note",
	"kind": "container",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["docker", "best-practice"],
}

findings contains finding if {
	some path, content in input.file_contents
	docker.is_dockerfile_path(path)
	some add in docker.adds(content)
	finding := {
		"rule_id": metadata.id,
		"message": "Use COPY instead of ADD.",
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("ADD %s", [add]),
	}
}
