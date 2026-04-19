# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_host_alias

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-15",
	"name": "Kubernetes pod must not manage host aliases",
	"description": "K8S_15: pods must not set spec.hostAliases.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_15",
	"languages": ["kubernetes", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "k8s",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "security", "host-access"],
}

findings contains finding if {
	some r in k8s.resources
	some pod in k8s.pods(r.doc)
	is_object(pod)
	aliases := object.get(pod.spec, "hostAliases", [])
	count(aliases) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s sets hostAliases.", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s/%s", [k8s.kind_of(r.doc), k8s.name_of(r.doc)]),
	}
}
