# Adapted from https://github.com/iamleot/conftest-policies
# Original License: BSD-2-Clause (see LICENSE).
# Helper package — not a rule (no metadata/findings).

package vulnetix.iamleot.github_actions_utils

import rego.v1

is_github_workflow_path(path) if regex.match(`(?i)\.github/workflows/[^/]+\.ya?ml$`, path)
