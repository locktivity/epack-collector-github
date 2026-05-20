#!/usr/bin/env bash
# Fails if the collector emits forbidden GitHub data. The GitHub API exposes
# many sensitive surfaces; this guard keeps them out of the artifact.
#
# Forbidden patterns:
#   .Body         - PR / issue / commit bodies (customer data)
#   .Patch        - commit patches / diffs (code contents)
#   .RawContent   - raw file contents
#   .GetContents( - the API call that returns file bytes; only safe inside the
#                   CODEOWNERS path where bytes are hashed then discarded
#   webhook_url   - full webhook URLs (can carry secrets); host only is allowed
#
# Suppress a deliberate, audited use with a trailing "// LINT-ALLOW: <reason>".
set -euo pipefail

violations=$(
  grep -rn -E '\.Body|\.Patch|\.RawContent|webhook_url|\.GetContents\(' \
    internal/collector/ \
    --include='*.go' \
    | grep -v '_test.go' \
    | grep -v '// LINT-ALLOW:' \
    || true
)

if [ -n "$violations" ]; then
  echo "FORBIDDEN GITHUB DATA EMISSION DETECTED:"
  echo "$violations"
  echo
  echo "If this use is deliberate and audited, append '// LINT-ALLOW: <reason>' to the line."
  exit 1
fi

echo "forbidden-data check: clean"
