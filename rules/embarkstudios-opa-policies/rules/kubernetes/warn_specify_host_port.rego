# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_host_port

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-11",
	"name": "Kubernetes container should not bind a hostPort",
	"description": "K8S_11: `hostPort` constrains scheduling; avoid unless required.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_11",
	"languages": ["kubernetes", "yaml"],
	"severity": "low",
	"level": "note",
	"kind": "k8s",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "reliability"],
}

findings contains finding if {
	some r in k8s.resources
	some c in k8s.containers(r.doc)
	ports := object.get(c, "ports", [])
	some p in ports
	is_object(p)
	hp := object.get(p, "hostPort", 0)
	hp != 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s container %q binds hostPort %v.", [k8s.kind_of(r.doc), k8s.name_of(r.doc), c.name, hp]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("hostPort=%v", [hp]),
	}
}
