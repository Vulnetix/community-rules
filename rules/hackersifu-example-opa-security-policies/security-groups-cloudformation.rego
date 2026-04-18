# Adapted from https://github.com/hackersifu/example_opa_security_policies
# Original License: Apache-2.0 (see LICENSE).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.hackersifu_sg_cloudformation

import rego.v1

metadata := {
	"id": "HKSF-SG-002",
	"name": "CloudFormation security group open SSH/RDP to 0.0.0.0/0",
	"description": "Detects `AWS::EC2::SecurityGroup` resources in CloudFormation templates whose ingress rules expose SSH (22) or RDP (3389) to 0.0.0.0/0.",
	"help_uri": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html",
	"languages": ["yaml", "json"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": [284, 668],
	"capec": ["CAPEC-560"],
	"attack_technique": ["T1133", "T1021.001"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "cloudformation", "security-group", "ssh", "rdp"],
}

_is_cfn(path) if endswith(lower(path), ".yaml")

_is_cfn(path) if endswith(lower(path), ".yml")

_is_cfn(path) if endswith(lower(path), ".json")

_is_cfn(path) if endswith(lower(path), ".template")

_looks_like_cfn(content) if contains(content, "AWS::EC2::SecurityGroup")

_line_of(content, offset) := line if {
	offset >= 0
	prefix := substring(content, 0, offset)
	newlines := regex.find_n(`\n`, prefix, -1)
	line := count(newlines) + 1
} else := 1

_dangerous_ports := {"22": "SSH", "3389": "RDP"}

# Scan for SecurityGroup ingress rules with ToPort: 22|3389 and CidrIp: 0.0.0.0/0
findings contains finding if {
	some path, content in input.file_contents
	_is_cfn(path)
	_looks_like_cfn(content)
	# Each ingress rule block in a YAML/JSON CFN template will contain ToPort and CidrIp lines near each other.
	rules := regex.find_n(`(?s)ToPort:\s*(\d+)[^}\]]{0,400}?CidrIp:\s*0\.0\.0\.0/0`, content, -1)
	some rule in rules
	port_parts := regex.find_n(`ToPort:\s*(\d+)`, rule, 1)
	count(port_parts) > 0
	port := regex.replace(port_parts[0], `\D`, "")
	_dangerous_ports[port]
	offset := indexof(content, rule)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("CloudFormation SecurityGroup ingress exposes %s (port %s) to 0.0.0.0/0.", [_dangerous_ports[port], port]),
		"artifact_uri": path,
		"severity": "critical",
		"level": "error",
		"start_line": _line_of(content, offset),
		"snippet": port_parts[0],
	}
}
