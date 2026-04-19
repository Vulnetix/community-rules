# Adapted from https://github.com/Scalr/sample-tf-opa-policies
# Ported to the Vulnetix Rego input schema (input.file_contents).
#
# Upstream walked the plan's configuration tree to distinguish constant
# values, variables, and data-source references. Under text scanning we can
# only enforce:
#   (1) any literal KMS key alias must be in `_allowed_kms_keys`
#   (2) KMS key ID / ARN attributes on supported resources must reference a
#       `data.aws_kms_key.*` source rather than a raw string.

package vulnetix.rules.scalr_enforce_kms_key_names

import rego.v1

import data.vulnetix.scalr.tf

metadata := {
	"id": "SCALR-AWS-0006",
	"name": "KMS-consuming resources must reference approved KMS keys",
	"description": "Literal KMS alias values must be in `_allowed_kms_keys`, and KMS key attributes on supported resources must reference `data.aws_kms_key.*` rather than literal IDs.",
	"help_uri": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/kms_key",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [311, 326],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "kms", "encryption"],
}

_allowed_kms_keys := {
	"pg-kms-key",
	"alias-1",
}

_kms_attr_keys := {
	"aws_ebs_volume": ["kms_key_id"],
	"aws_ebs_default_kms_key": ["key_arn"],
	"aws_db_instance": ["kms_key_id", "performance_insights_kms_key_id"],
	"aws_rds_cluster": ["kms_key_id"],
	"aws_rds_cluster_instance": ["performance_insights_kms_key_id"],
	"aws_cloudtrail": ["kms_key_id"],
	"aws_cloudwatch_log_group": ["kms_key_id"],
	"aws_dynamodb_table": ["kms_key_arn"],
	"aws_elastictranscoder_pipeline": ["aws_kms_key_arn"],
	"aws_redshift_cluster": ["kms_key_id"],
	"aws_redshift_snapshot_copy_grant": ["kms_key_id"],
	"aws_secretsmanager_secret": ["kms_key_id"],
	"aws_ssm_parameter": ["key_id"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some block in tf.data_blocks(content, "aws_kms_key")
	alias := tf.string_attr(block, "key_id")
	stripped := trim_prefix(alias, "alias/")
	not _allowed_kms_keys[stripped]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("data.aws_kms_key %q references KMS alias %q which is not approved.", [tf.resource_name(block), alias]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": alias,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some t, attrs in _kms_attr_keys
	some block in tf.resource_blocks(content, t)
	some attr in attrs
	val := tf.string_attr(block, attr)
	not _is_kms_data_ref(val)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s %q sets %s to literal %q — must reference data.aws_kms_key.*", [t, tf.resource_name(block), attr, val]),
		"artifact_uri": path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": val,
	}
}

_is_kms_data_ref(val) if startswith(val, "${data.aws_kms_key.")

_is_kms_data_ref(val) if startswith(val, "data.aws_kms_key.")
