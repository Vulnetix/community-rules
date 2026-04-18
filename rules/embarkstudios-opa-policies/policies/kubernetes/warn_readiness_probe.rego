# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_readiness_probe

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-21",
	"name": "Kubernetes container should declare readinessProbe",
	"description": "K8S_21: workload containers must declare a readinessProbe.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_21",
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
	k8s.is_workload(r.doc)
	some c in k8s.containers(r.doc)
	not object.get(c, "readinessProbe", false)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s container %q has no readinessProbe.", [k8s.kind_of(r.doc), k8s.name_of(r.doc), c.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s:%s", [k8s.name_of(r.doc), c.name]),
	}
}
