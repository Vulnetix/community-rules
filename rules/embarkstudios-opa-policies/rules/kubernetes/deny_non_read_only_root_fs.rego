# Adapted from https://github.com/EmbarkStudios/opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.embark_k8s_read_only_root_fs

import rego.v1

import data.vulnetix.embark.k8s

metadata := {
	"id": "EMBARK-K8S-14",
	"name": "Kubernetes container must use a read-only root filesystem",
	"description": "K8S_14: containers must set securityContext.readOnlyRootFilesystem=true.",
	"help_uri": "https://github.com/EmbarkStudios/opa-policies/wiki/K8S_14",
	"languages": ["kubernetes", "yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "k8s",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "security", "hardening"],
}

findings contains finding if {
	some r in k8s.resources
	some c in k8s.containers(r.doc)
	not object.get(object.get(c, "securityContext", {}), "readOnlyRootFilesystem", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s container %q does not use a read-only root filesystem.", [k8s.kind_of(r.doc), k8s.name_of(r.doc), c.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("%s:%s", [k8s.name_of(r.doc), c.name]),
	}
}
