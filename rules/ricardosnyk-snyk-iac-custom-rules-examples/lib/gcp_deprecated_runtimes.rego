# Adapted from https://github.com/ricardosnyk/snyk-iac-custom-rules-examples
# Helper package — not a rule (no metadata/findings).

package vulnetix.ricardosnyk.gcp_deprecated_runtimes

import rego.v1

dep_runtimes := {"nodejs8", "nodejs6", "go111"}
