# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_docker_port_range

import rego.v1

import data.vulnetix.embark.docker

metadata := {
	"id": "EMBARK-DOCKER-07",
	"name": "Dockerfile EXPOSE must use a valid port",
	"description": "DOCKER_07: EXPOSE values must be between 1 and 65534.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/DOCKER_07",
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
	some port_str in docker.exposes(content)
	port := _port_number(port_str)
	not _valid_port(port)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("EXPOSE %s is outside 1-65534.", [port_str]),
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("EXPOSE %s", [port_str]),
	}
}

_port_number(p) := to_number(split(p, "/")[0])

_valid_port(n) if {
	n > 0
	n < 65535
}
