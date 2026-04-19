# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_mount_docker_socket

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-10",
	"name": "Kubernetes pod must not mount the Docker socket",
	"description": "K8S_10: pods must not mount /var/run/docker.sock via hostPath.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_10",
	"languages": ["kubernetes", "yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "k8s",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": ["T1611"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "security", "container-escape"],
}

findings contains finding if {
	some r in k8s.resources
	some v in k8s.volumes(r.doc)
	object.get(v.hostPath, "path", "") == "/var/run/docker.sock"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s mounts the Docker socket.", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
		"artifact_uri": r.path,
		"severity": "critical",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s/%s", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
	}
}
