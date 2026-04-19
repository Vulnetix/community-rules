# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_privilege_escalation

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-01",
	"name": "Kubernetes container must not allow privilege escalation",
	"description": "K8S_01: `allowPrivilegeEscalation` must not be true on any container.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_01",
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
	some c in k8s.containers(r.doc)
	object.get(c.securityContext, "allowPrivilegeEscalation", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s container %q allows privilege escalation.", [k8s.kind_of(r.doc), k8s.name_of(r.doc), c.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s/%s:%s", [k8s.kind_of(r.doc), k8s.name_of(r.doc), c.name]),
	}
}
