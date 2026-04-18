# Adapted from https://github.com/rallyhealth/conftest-policy-packs
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.rally_nodejs_publish_config

import rego.v1

import data.vulnetix.rallyhealth.packages_utils

metadata := {
	"id": "PKGSEC-0003",
	"name": "NPM packages must publish to an approved registry",
	"description": "`package.json` must declare `publishConfig.registry` pointing at an approved organizational registry (fork and tailor `_approved_registries`).",
	"help_uri": "https://docs.npmjs.com/cli/v7/using-npm/registry#how-can-i-prevent-my-package-from-being-published-in-the-official-registry",
	"languages": ["json"],
	"severity": "medium",
	"level": "warning",
	"kind": "sca",
	"cwe": [1357],
	"capec": [],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["nodejs", "package.json", "supply-chain"],
}

_approved_registries := [
	"https://my.private.registry/repository/npm-private/",
]

findings contains finding if {
	some path, content in input.file_contents
	packages_utils.is_package_json(path)
	pkg := packages_utils.parse_pkg(content)
	pkg.publishConfig.registry
	registry := pkg.publishConfig.registry
	not _is_approved(registry)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("publishConfig.registry %q is not an approved registry. Approved: %v.", [registry, _approved_registries]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": registry,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	packages_utils.is_package_json(path)
	pkg := packages_utils.parse_pkg(content)
	pkg.publishConfig
	not pkg.publishConfig.registry
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("publishConfig is set but missing the `registry` field. Approved registries: %v.", [_approved_registries]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": "",
	}
}

findings contains finding if {
	some path, content in input.file_contents
	packages_utils.is_package_json(path)
	pkg := packages_utils.parse_pkg(content)
	not pkg.publishConfig
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("package.json declares no publishConfig; this will default to the public npm registry. Approved registries: %v.", [_approved_registries]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": "",
	}
}

_is_approved(registry) if {
	some r in _approved_registries
	r == registry
}
