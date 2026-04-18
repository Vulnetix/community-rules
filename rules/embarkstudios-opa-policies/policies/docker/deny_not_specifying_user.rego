# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_docker_no_user

import rego.v1

import data.vulnetix.embark.docker

metadata := {
	"id": "EMBARK-DOCKER-01",
	"name": "Dockerfile must set USER explicitly",
	"description": "DOCKER_01: if USER is not specified the container runs as root implicitly.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/DOCKER_01",
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

findings contains finding if {
	some path, content in input.file_contents
	docker.is_dockerfile_path(path)
	not docker.has_user_set(content)
	finding := {
		"rule_id": metadata.id,
		"message": "Dockerfile does not set USER; container runs as root.",
		"artifact_uri": path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": "USER",
	}
}
