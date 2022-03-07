#!/usr/bin/env bats

load '/usr/local/lib/bats/load.bash'
# shellcheck source=lib/interface.bash
load '../lib/ecr'

#
# Tests for ECR scan results communication
#

# Uncomment the following line to debug stub failures
# export [stub_command]_STUB_DEBUG=/dev/tty
# export AWS_STUB_DEBUG=/dev/tty


@test "When scan result is not found, it fails with a helpful error message" {
  skip
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
  assert_line --partial "buildkite-agent annotate --style warning --context exit_reason_imagelabel No ECR vulnerability scan available for image:"

  unset get_ecr_image_digest
  unset poll_ecr_scan_result

  unstub buildkite-agent
}

@test "When image is unsupported, it fails with a helpful error message" {
  skip
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
  assert_line --partial "buildkite-agent annotate --style warning --context exit_reason_imagelabel Warning: ECR vulnerability scan does not support"

  unset get_ecr_image_digest
  unset poll_ecr_scan_result

  unstub buildkite-agent
}

@test "When AWS takes time to produce an image, it checks multiple times until the image is available and succeeds" {
  skip
  registry="012345678912"
  repository="repo-name"
  image_id="imageDigest=image-digest"

  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME="012345678912.dkr.ecr.us-west-2.amazonaws.com/repo-name:image-tag"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_CRITICALS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_HIGHS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_LABEL="imagelabel"
  export POLL_ATTEMPTS="3"

  scan_findings_base_args="--registry-id ${registry} --repository-name ${repository} --image-id ${image_id} --no-paginate"
  scan_findings_status="${scan_findings_base_args} --query imageScanStatus.status --output text"

  stub aws \
    "ecr describe-images * : echo image-digest" \
    "ecr describe-image-scan-findings ${scan_findings_status} : echo IN_PROGRESS" \
    "ecr describe-image-scan-findings ${scan_findings_status} : echo PENDING" \
    "ecr describe-image-scan-findings ${scan_findings_status} : echo COMPLETE" \
    "ecr describe-image-scan-findings * : echo 0" \
    "ecr describe-image-scan-findings * : echo 0"

  stub sleep \
    '* : echo 1>&2 sleep $@' \
    '* : echo 1>&2 sleep $@' \
    '* : echo 1>&2 sleep $@'

  stub buildkite-agent '* : echo buildkite-agent $@'

  run "$PWD/hooks/post-command"

  assert_success
  assert_line --partial "buildkite-agent annotate --style info --context vuln_counts_imagelabel #### Vulnerability summary for \"imagelabel\" - Critical: 0 - High: 0"

  unstub aws
  unstub sleep
  unstub buildkite-agent
}
