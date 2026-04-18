# Adapted from https://github.com/hackersifu/example_opa_security_policies
# Original License: Apache-2.0 (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.hackersifu_sg_terraform

import rego.v1

metadata := {
	"id": "HKSF-SG-001",
	"name": "Terraform security group open SSH/RDP to 0.0.0.0/0",
	"description": "Detects `aws_security_group` ingress blocks exposing SSH (22) or RDP (3389) to 0.0.0.0/0.",
	"help_uri": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html",
	"languages": ["terraform"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": [284, 668],
	"capec": ["CAPEC-560"],
	"attack_technique": ["T1133", "T1021.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "security-group", "ssh", "rdp", "terraform"],
}

_is_tf(path) if endswith(lower(path), ".tf")

_line_of(content, offset) := line if {
	offset >= 0
	prefix := substring(content, 0, offset)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

_dangerous_ports := {
	"22": "SSH",
	"3389": "RDP",
}

# Match ingress blocks with to_port = <dangerous> and cidr_blocks containing "0.0.0.0/0"
findings contains finding if {
	some path, content in input.file_contents
	_is_tf(path)
	# Find ingress blocks inside aws_security_group resources.
	blocks := regex.find_n(`(?s)ingress\s*\{[^{}]*?\}`, content, -1)
	some block in blocks
	port_parts := regex.find_n(`to_port\s*=\s*(\d+)`, block, 1)
	count(port_parts) > 0
	port := regex.replace(port_parts[0], `\D`, "")
	_dangerous_ports[port]
	contains(block, "0.0.0.0/0")
	offset := indexof(content, block)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Security group ingress exposes %s (port %s) to 0.0.0.0/0.", [_dangerous_ports[port], port]),
		"artifact_uri": path,
		"severity": "critical",
		"level": "error",
		"start_line": _line_of(content, offset),
		"snippet": port_parts[0],
	}
}
