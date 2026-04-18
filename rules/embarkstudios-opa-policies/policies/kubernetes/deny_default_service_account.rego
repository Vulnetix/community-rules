# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_default_sa

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-06",
	"name": "Kubernetes pod must not use the default service account",
	"description": "K8S_06: serviceAccountName must be set explicitly and not equal \"default\".",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_06",
	"languages": ["kubernetes", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "k8s",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "security", "rbac"],
}

findings contains finding if {
	some r in k8s.resources
	some pod in k8s.pods(r.doc)
	_default_sa(pod)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s uses the default service account.", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s/%s", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
	}
}

_default_sa(pod) if object.get(pod.spec, "serviceAccountName", "default") == "default"
