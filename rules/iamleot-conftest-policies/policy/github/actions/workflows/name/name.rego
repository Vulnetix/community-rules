# Adapted from https://github.com/iamleot/conftest-policies
# Original License: BSD-2-Clause (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.iamleot_gha_name

import rego.v1

import data.vulnetix.iamleot.github_actions_utils as utils

metadata := {
	"id": "IAMLEOT-GHA-NAME-001",
	"name": "GitHub Actions workflow/job/step should have a name",
	"description": "GitHub Actions workflows, jobs, and steps should declare a `name:` key for readability and to avoid machine-generated names in the UI.",
	"help_uri": "https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["github-actions", "readability"],
}

_line_of(content, offset) := line if {
	offset >= 0
	prefix := substring(content, 0, offset)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

# Workflow missing top-level name
findings contains finding if {
	some path, content in input.file_contents
	utils.is_github_workflow_path(path)
	not regex.match(`(?m)^name\s*:`, content)
	finding := {
		"rule_id": metadata.id,
		"message": "Workflow should have a top-level `name` key.",
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": 1,
		"snippet": "",
	}
}

# Job missing name: detect job-level keys (2-space indent) with no name: sibling.
findings contains finding if {
	some path, content in input.file_contents
	utils.is_github_workflow_path(path)
	# Crude: find job definitions (2-space-indented key blocks under `jobs:`)
	jobs_section := regex.find_n(`(?s)^jobs\s*:.*`, content, 1)
	count(jobs_section) > 0
	job_blocks := regex.find_n(`(?m)^  ([A-Za-z0-9_-]+)\s*:\s*$`, jobs_section[0], -1)
	some job_block in job_blocks
	job_name_match := regex.find_n(`^  ([A-Za-z0-9_-]+)`, job_block, 1)
	count(job_name_match) > 0
	job_id := trim_space(regex.replace(job_name_match[0], `:`, ""))
	# Look for a name: line within a reasonable distance after the job header.
	job_offset := indexof(content, job_block)
	job_offset >= 0
	block_end := job_offset + 500
	block_end_clamped := min([block_end, count(content)])
	block_body := substring(content, job_offset, block_end_clamped - job_offset)
	not regex.match(`(?m)^    name\s*:`, block_body)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Job `%s` should have a `name` key.", [job_id]),
		"artifact_uri": path,
		"severity": "low",
		"level": "note",
		"start_line": _line_of(content, job_offset),
		"snippet": trim_space(job_block),
	}
}
