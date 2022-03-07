#!/usr/bin/env bash

function notify_error {
    local exit_statement="
A failure occurred while attempting to retrieve ECR scan results.

This will not block CI, but please notify the ecr-scan-plugin maintainers of the issue.
"

  echo "^^^ +++"
  echo "${exit_statement}"

  # try to add an annotation, but skip if it doesn't work
  buildkite-agent annotate --style warning "${exit_statement}" || true

  exit 0
}

function soft_failure {
  local exit_statement="${1}"
  local image_label="${2}"

  echo "^^^ +++"
  echo "${exit_statement}"

  # try to add an annotation, but skip if it doesn't work
  buildkite-agent annotate --context "ecr_scan_results_failed_${image_label}" --style warning "${exit_statement}" || true

  exit 0
}

function configuration_error {
  local message="${1}"

  1>&2 printf "+++ ❌ ECR scan results plugin configuration error\n\n%s\n\n" "${message}"
  exit 1
}
