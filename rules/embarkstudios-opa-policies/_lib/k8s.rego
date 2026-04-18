# Adapted from EmbarkStudios/opa-policies.
# Kubernetes-YAML detection and parsing helpers for the Vulnetix port.

package vulnetix.embark.k8s

import rego.v1

is_yaml_path(path) if endswith(lower(path), ".yaml")

is_yaml_path(path) if endswith(lower(path), ".yml")

# Split a (possibly multi-doc) YAML stream into individual parsed resources,
# returning only those that look like Kubernetes manifests (have `kind`).
docs(content) := out if {
	raw := yaml.unmarshal(sprintf("---\n%s", [content]))
	is_array(raw)
	out := [d | some d in raw; is_object(d); is_string(d.kind)]
} else := out if {
	# fallback: single doc
	single := yaml.unmarshal(content)
	is_object(single)
	is_string(single.kind)
	out := [single]
} else := []

# resources contains a {path, doc} entry for every parsed Kubernetes resource
# in every YAML file under input.file_contents.
resources contains out if {
	some path, content in input.file_contents
	is_yaml_path(path)
	some doc in docs(content)
	out := {"path": path, "doc": doc}
}

is_service(doc) := doc.kind == "Service"

is_pod(doc) := doc.kind == "Pod"

is_namespace(doc) := doc.kind == "Namespace"

is_workload(doc) if {
	doc.kind in {"DaemonSet", "Deployment", "GameServer", "StatefulSet", "ReplicaSet", "ReplicationController"}
}

is_job(doc) if {
	doc.kind in {"CronJob", "Job"}
}

is_namespace_scoped_kind(doc) if {
	not doc.kind in {
		"Namespace", "ClusterRole", "ClusterRoleBinding", "PriorityClass",
		"PersistentVolume", "APIService", "CustomResourceDefinition",
		"StorageClass", "CSIDriver", "PodSecurityPolicy",
		"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
		"ComputeClass",
	}
}

# Pull pod template / pod out of a resource.
pods(doc) := pods if {
	is_workload(doc)
	pods := [doc.spec.template]
} else := pods if {
	is_pod(doc)
	pods := [doc]
} else := pods if {
	is_job(doc)
	pods := [doc.spec.jobTemplate.spec.template]
} else := []

pod_containers(pod) := all if {
	keys := ["containers", "initContainers"]
	all := [c |
		some k in keys
		cs := object.get(pod.spec, k, [])
		is_array(cs)
		some c in cs
		is_object(c)
	]
}

containers(doc) := out if {
	pods_list := pods(doc)
	out := [c |
		some pod in pods_list
		is_object(pod)
		some c in pod_containers(pod)
	]
}

volumes(doc) := out if {
	pods_list := pods(doc)
	out := [v |
		some pod in pods_list
		is_object(pod)
		vols := object.get(pod.spec, "volumes", [])
		is_array(vols)
		some v in vols
		is_object(v)
	]
}

name_of(doc) := object.get(doc.metadata, "name", "")

kind_of(doc) := doc.kind

added_capability(container, cap) if {
	caps := object.get(container.securityContext.capabilities, "add", [])
	cap in caps
}
