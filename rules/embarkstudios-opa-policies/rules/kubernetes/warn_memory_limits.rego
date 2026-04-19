# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_memory_limits

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-12",
	"name": "Kubernetes container must declare memory limits",
	"description": "K8S_12: resources.limits.memory must be set.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_12",
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
	not object.get(object.get(c.resources, "limits", {}), "memory", "")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s container %q has no memory limit.", [k8s.kind_of(r.doc), k8s.name_of(r.doc), c.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s:%s", [k8s.name_of(r.doc), c.name]),
	}
}
