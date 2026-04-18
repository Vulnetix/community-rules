# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_host_ipc

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-16",
	"name": "Kubernetes pod must not share host IPC",
	"description": "K8S_16: pods must not set spec.hostIPC=true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_16",
	"languages": ["kubernetes", "yaml"],
	"severity": "high",
	"level": "error",
	"kind": "k8s",
	"cwe": ["CWE-653"],
	"capec": [],
	"attack_technique": ["T1611"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "security", "isolation"],
}

findings contains finding if {
	some r in k8s.resources
	some pod in k8s.pods(r.doc)
	is_object(pod)
	object.get(pod.spec, "hostIPC", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s shares host IPC namespace.", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s/%s", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
	}
}
