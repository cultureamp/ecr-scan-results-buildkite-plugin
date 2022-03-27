#!/usr/bin/env bats

load '/usr/local/lib/bats/load.bash'
# shellcheck source=lib/interface.bash
load '../lib/interface'

#
# Tests for top-level interface and flow
#

# Uncomment the following line to debug stub failures
# export [stub_command]_STUB_DEBUG=/dev/tty
# export AWS_STUB_DEBUG=/dev/tty

@test "When I don't supply image-name, it fails with a helpful error message" {
  run post_command

  assert_failure
  assert_line "No 'image-name' argument provided, or not in required format."
}

@test "When I supply image-name in an incorrect format, it fails with a helpful error message" {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME="wrong format for image name"

  run "$PWD/hooks/post-command"

  assert_failure
  assert_line "No 'image-name' argument provided, or not in required format."
}

@test "When I supply max-criticals in an incorrect format, it fails with a helpful error message" {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME="012345678912.dkr.ecr.us-west-2.amazonaws.com/repo-name:image-tag"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_CRITICALS="not an integer"

  run "$PWD/hooks/post-command"

  assert_failure
  assert_line --partial "'max-criticals' argument must be a positive integer"
}

@test "When I supply max-highs in an incorrect format, it fails with a helpful error message" {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME="012345678912.dkr.ecr.us-west-2.amazonaws.com/repo-name:image-tag"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_CRITICALS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_HIGHS="not an integer"

  run "$PWD/hooks/post-command"

  assert_failure
  assert_line --partial "'max-highs' argument must be a positive integer"
}

@test "When I supply image-label in an incorrect format, it fails with a helpful error message" {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME="012345678912.dkr.ecr.us-west-2.amazonaws.com/repo-name:image-tag"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_CRITICALS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_HIGHS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_LABEL="-incorrectD format"

  run "$PWD/hooks/post-command"

  assert_failure
  assert_line --partial "'image-label' argument must be an alphanumeric string"
}

@test "When scan result is not found, and image-label is not provided, it fails with a helpful error message" {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME="012345678912.dkr.ecr.us-west-2.amazonaws.com/repo-name:image-tag"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_CRITICALS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_HIGHS="0"
  export POLL_ATTEMPTS="1"

  function get_ecr_image_digest() { echo "image-digest"; }
  export -f get_ecr_image_digest

  function poll_ecr_scan_result() { echo "SCAN_NOT_PRESENT"; }
  export -f poll_ecr_scan_result

  stub buildkite-agent '* : echo buildkite-agent $@'

  run post_command

  assert_success
  assert_line --partial "No ECR vulnerability scan available for image"
  assert_line --partial "buildkite-agent annotate --context ecr_scan_results_failed_ --style warning No ECR vulnerability scan available for image:"

  unset get_ecr_image_digest
  unset poll_ecr_scan_result

  unstub buildkite-agent
}

@test "When scan result is not found, and image-label is provided, it fails with a helpful error message" {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME="012345678912.dkr.ecr.us-west-2.amazonaws.com/repo-name:image-tag"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_CRITICALS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_HIGHS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_LABEL="imagelabel"
  export POLL_ATTEMPTS="1"

  function get_ecr_image_digest() { echo "image-digest"; }
  export -f get_ecr_image_digest

  function poll_ecr_scan_result() { echo "SCAN_NOT_PRESENT"; }
  export -f poll_ecr_scan_result

  stub buildkite-agent '* : echo buildkite-agent $@'

  run post_command

  assert_success
  assert_line --partial "No ECR vulnerability scan available for image"
  assert_line --partial "buildkite-agent annotate --context ecr_scan_results_failed_imagelabel --style warning No ECR vulnerability scan available for image:"

  unset get_ecr_image_digest
  unset poll_ecr_scan_result

  unstub buildkite-agent
}

@test "When image is unsupported, it fails with a helpful error message" {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME="012345678912.dkr.ecr.us-west-2.amazonaws.com/repo-name:image-tag"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_CRITICALS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_HIGHS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_LABEL="imagelabel"
  export POLL_ATTEMPTS="1"

  function get_ecr_image_digest() { echo "image-digest"; }
  export -f get_ecr_image_digest

  function poll_ecr_scan_result() { echo "UNSUPPORTED_IMAGE"; }
  export -f poll_ecr_scan_result

  stub buildkite-agent '* : echo buildkite-agent $@'

  run post_command

  assert_success
  assert_line --partial "Warning: ECR vulnerability scan does not support this image type"
  assert_line --partial "buildkite-agent annotate --context ecr_scan_results_failed_imagelabel --style warning Warning: ECR vulnerability scan does not support"

  unset get_ecr_image_digest
  unset poll_ecr_scan_result

  unstub buildkite-agent
}

@test "When scan is available, it succeeds and annotates the build" {
  registry="012345678912"
  repository="repo-name"
  image_id="imageDigest=image-digest"

  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME="012345678912.dkr.ecr.us-west-2.amazonaws.com/repo-name:image-tag"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_CRITICALS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_HIGHS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_LABEL="imagelabel"
  export POLL_ATTEMPTS="3"

  function get_ecr_image_digest() { echo "image-digest"; }
  export -f get_ecr_image_digest

  function poll_ecr_scan_result() { echo "COMPLETE"; }
  export -f poll_ecr_scan_result

  stub aws \
    "ecr describe-image-scan-findings * : echo 0" \
    "ecr describe-image-scan-findings * : echo 0"
  stub buildkite-agent '* : echo buildkite-agent $@'

  run post_command

  assert_success
  assert_line --partial "buildkite-agent annotate --style info --context vuln_counts_imagelabel #### Vulnerability summary for \"imagelabel\" - Critical: 0 - High: 0"

  unstub aws
  unstub buildkite-agent
}
