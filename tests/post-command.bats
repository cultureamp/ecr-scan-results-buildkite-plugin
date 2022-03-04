#!/usr/bin/env bats

load '/usr/local/lib/bats/load.bash'

# Uncomment the following line to debug stub failures
# export BUILDKITE_AGENT_STUB_DEBUG=/dev/tty

@test "When I don't supply image-name, it fails with a helpful error message" {
  run "$PWD/hooks/post-command"

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

@test "When AWS fails to find a scan after multiple attempts, it fails with a helpful error message" {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME="012345678912.dkr.ecr.us-west-2.amazonaws.com/repo-name:image-tag"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_CRITICALS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_HIGHS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_LABEL="imagelabel"
  export POLL_ATTEMPTS="1"

  function get_ecr_image_digest() { echo "image-digest"; }
  export -f get_ecr_image_digest

  stub aws \
    'ecr describe-images * : echo image-digest' \
    'ecr describe-image-scan-findings * : echo SCAN_NOT_PRESENT'

  stub sleep '* : echo 1>&2 sleep $@'
  stub buildkite-agent '* : echo buildkite-agent $@'

  run "$PWD/hooks/post-command"

  assert_success
  assert_line --partial "No ECR vulnerability scan available for image"
  assert_line --partial "buildkite-agent annotate --style warning --context exit_reason_imagelabel No ECR vulnerability scan available for image:"

  unset get_ecr_image_digest

  unstub aws
  unstub sleep
  unstub buildkite-agent
}

@test "When AWS indicates image is unsupported, it fails with a helpful error message" {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME="012345678912.dkr.ecr.us-west-2.amazonaws.com/repo-name:image-tag"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_CRITICALS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_MAX_HIGHS="0"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_LABEL="imagelabel"
  export POLL_ATTEMPTS="1"

  stub aws \
    'ecr describe-images * : echo image-digest' \
    'ecr describe-image-scan-findings * : echo UNSUPPORTED_IMAGE'

  stub sleep '* : echo 1>&2 sleep $@'
  stub buildkite-agent '* : echo buildkite-agent $@'

  run "$PWD/hooks/post-command"

  assert_success
  assert_line --partial "Warning: ECR vulnerability scan does not support this image type"
  assert_line --partial "buildkite-agent annotate --style warning --context exit_reason_imagelabel Warning: ECR vulnerability scan does not support"

  unstub aws
  unstub sleep
  unstub buildkite-agent
}

@test "When AWS takes time to produce an image, it checks multiple times until the image is available and succeeds" {
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
