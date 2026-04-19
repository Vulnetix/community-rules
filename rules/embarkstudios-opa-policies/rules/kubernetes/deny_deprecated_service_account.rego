# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_deprecated_sa_field

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-07",
	"name": "Kubernetes pod must not use the deprecated serviceAccount field",
	"description": "K8S_07: `spec.serviceAccount` is deprecated; use `spec.serviceAccountName`.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_07",
	"languages": ["kubernetes", "yaml"],
	"severity": "low",
	"level": "note",
	"kind": "k8s",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "deprecation"],
}

findings contains finding if {
	some r in k8s.resources
	some pod in k8s.pods(r.doc)
	object.get(pod.spec, "serviceAccount", "")
	pod.spec.serviceAccount != ""
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s uses deprecated spec.serviceAccount; use serviceAccountName.", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s/%s", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
	}
}
