# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_run_as_root

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-02",
	"name": "Kubernetes pods must runAsNonRoot",
	"description": "K8S_02: Either pod or every container must set securityContext.runAsNonRoot=true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_02",
	"languages": ["kubernetes", "yaml"],
	"severity": "high",
	"level": "error",
	"kind": "k8s",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "security", "least-privilege"],
}

findings contains finding if {
	some r in k8s.resources
	some pod in k8s.pods(r.doc)
	_running_as_root(pod)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s runs as root.", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s/%s", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
	}
}

_running_as_root(pod) if {
	object.get(pod.spec.securityContext, "runAsNonRoot", false) != true
	some c in k8s.pod_containers(pod)
	object.get(c.securityContext, "runAsNonRoot", false) != true
}
