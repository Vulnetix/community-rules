# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_default_namespace

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-04",
	"name": "Kubernetes namespaced resources must set a non-default namespace",
	"description": "K8S_04: workloads must declare metadata.namespace != \"default\".",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_04",
	"languages": ["kubernetes", "yaml"],
	"severity": "low",
	"level": "note",
	"kind": "k8s",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "governance"],
}

findings contains finding if {
	some r in k8s.resources
	k8s.is_namespace_scoped_kind(r.doc)
	ns := object.get(r.doc.metadata, "namespace", "default")
	ns == "default"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s is in the default namespace.", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": sprintf("%s/%s", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
	}
}
