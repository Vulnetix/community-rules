# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_cap_sysadmin

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-05",
	"name": "Kubernetes container must not add CAP_SYS_ADMIN",
	"description": "K8S_05: securityContext.capabilities.add must not include CAP_SYS_ADMIN.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_05",
	"languages": ["kubernetes", "yaml"],
	"severity": "high",
	"level": "error",
	"kind": "k8s",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "security", "capabilities"],
}

findings contains finding if {
	some r in k8s.resources
	some c in k8s.containers(r.doc)
	k8s.added_capability(c, "CAP_SYS_ADMIN")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s container %q adds CAP_SYS_ADMIN.", [k8s.kind_of(r.doc), k8s.name_of(r.doc), c.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("%s/%s:%s", [k8s.kind_of(r.doc), k8s.name_of(r.doc), c.name]),
	}
}
