# Adapted from https://github.com/int128/conftest-docker-hub-image-pull-secrets
# Original License: Apache-2.0 (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.int128_docker_hub_image_pull_secrets

import rego.v1

metadata := {
	"id": "INT128-K8S-001",
	"name": "Docker Hub image pulls require imagePullSecrets",
	"description": "Kubernetes workloads (Deployment/StatefulSet/DaemonSet/Job) referencing Docker Hub images must declare `imagePullSecrets`, and must not declare them when only non-Docker-Hub images are used.",
	"help_uri": "https://github.com/int128/conftest-docker-hub-image-pull-secrets",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [1021],
	"capec": [],
	"attack_technique": ["T1195"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "docker-hub", "image-pull-secrets"],
}

_is_k8s_manifest(path) if endswith(lower(path), ".yaml")

_is_k8s_manifest(path) if endswith(lower(path), ".yml")

_workload_kinds := {"Deployment", "Job", "StatefulSet", "DaemonSet"}

# Split a full file into logical YAML documents (separator: lines starting with `---`).
_split_docs(content) := docs if {
	separator := regex.find_n(`(?m)^---\s*$`, content, -1)
	count(separator) > 0
	docs := regex.split(`(?m)^---\s*$`, content)
} else := [content]

_doc_kind(doc) := kind if {
	match := regex.find_n(`(?m)^kind:\s*([A-Za-z0-9]+)\s*$`, doc, 1)
	count(match) > 0
	parts := regex.split(`\s+`, trim_space(match[0]))
	kind := parts[1]
}

_doc_name(doc) := name if {
	match := regex.find_n(`(?m)^\s{0,4}name:\s*([^\s#]+)`, doc, 1)
	count(match) > 0
	parts := regex.split(`\s+`, trim_space(match[0]))
	name := parts[1]
} else := "<unnamed>"

_doc_has_image_pull_secrets(doc) if {
	regex.match(`(?m)^\s*imagePullSecrets\s*:`, doc)
}

_images_in_doc(doc) := images if {
	matches := regex.find_n(`(?m)^\s*-?\s*image:\s*["']?([^\s"'#]+)`, doc, -1)
	images := [img |
		some m in matches
		img_parts := regex.split(`image:\s*["']?`, m)
		count(img_parts) == 2
		raw := img_parts[1]
		stripped := regex.replace(raw, `["']`, "")
		img := trim_space(stripped)
		img != ""
	]
}

_is_docker_hub_image(image) if {
	not contains(image, "/")
	not contains(image, ".")
}

_is_docker_hub_image(image) if {
	parts := split(image, "/")
	count(parts) == 2
	not contains(parts[0], ".")
	not contains(parts[0], ":")
}

_is_docker_hub_image(image) if {
	startswith(image, "library/")
}

_line_of(content, doc) := line if {
	prefix_end := indexof(content, doc)
	prefix_end >= 0
	prefix := substring(content, 0, prefix_end)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

# Missing imagePullSecrets when Docker Hub image is used
findings contains finding if {
	some path, content in input.file_contents
	_is_k8s_manifest(path)
	some doc in _split_docs(content)
	kind := _doc_kind(doc)
	kind in _workload_kinds
	not _doc_has_image_pull_secrets(doc)
	some img in _images_in_doc(doc)
	_is_docker_hub_image(img)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s references Docker Hub image %q without imagePullSecrets", [kind, _doc_name(doc), img]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": _line_of(content, doc),
		"snippet": sprintf("kind: %s; image: %s", [kind, img]),
	}
}

# Unnecessary imagePullSecrets when no Docker Hub image is used
findings contains finding if {
	some path, content in input.file_contents
	_is_k8s_manifest(path)
	some doc in _split_docs(content)
	kind := _doc_kind(doc)
	kind in _workload_kinds
	_doc_has_image_pull_secrets(doc)
	images := _images_in_doc(doc)
	count(images) > 0
	every img in images {
		not _is_docker_hub_image(img)
	}
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s/%s declares imagePullSecrets but uses no Docker Hub images", [kind, _doc_name(doc)]),
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": _line_of(content, doc),
		"snippet": sprintf("kind: %s", [kind]),
	}
}
