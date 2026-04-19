# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_latest_tag

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-03",
	"name": "Kubernetes container images must pin a non-latest tag",
	"description": "K8S_03: container image must not use the :latest tag.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_03",
	"languages": ["kubernetes", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "k8s",
	"cwe": ["CWE-1357"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "supply-chain"],
}

findings contains finding if {
	some r in k8s.resources
	some c in k8s.containers(r.doc)
	parts := split(c.image, ":")
	count(parts) >= 2
	lower(parts[1]) == "latest"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s container %q uses :latest (%s).", [k8s.kind_of(r.doc), k8s.name_of(r.doc), c.name, c.image]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": c.image,
	}
}
