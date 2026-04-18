# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_run_as_user_too_low

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-19",
	"name": "Kubernetes container must run as a high UID",
	"description": "K8S_19: containers must set securityContext.runAsUser >= 10000.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_19",
	"languages": ["kubernetes", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "k8s",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "security", "hardening"],
}

findings contains finding if {
	some r in k8s.resources
	some c in k8s.containers(r.doc)
	uid := object.get(object.get(c, "securityContext", {}), "runAsUser", -1)
	is_number(uid)
	uid >= 0
	uid < 10000
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s container %q runs as UID %v (below 10000).", [k8s.kind_of(r.doc), k8s.name_of(r.doc), c.name, uid]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("runAsUser=%v", [uid]),
	}
}
