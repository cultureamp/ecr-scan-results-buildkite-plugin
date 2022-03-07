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


@test "When scan result is not found, it returns SCAN_NOT_PRESENT" {
  local registry_id="012345678912"
  local repo_name="repo-name"
  local image_identifier="imageDigest=image-hash"
  local poll_attempts="1"

  scan_findings_base_args="--registry-id ${registry_id} --repository-name ${repo_name} --image-id ${image_identifier} --no-paginate"
  scan_findings_status="${scan_findings_base_args} --query imageScanStatus.status --output text"

  stub aws \
    "ecr describe-image-scan-findings ${scan_findings_status} : echo something.ScanNotFoundException Image scan not found; exit 1"

  run poll_ecr_scan_result "${registry_id}" "${repo_name}" "${image_identifier}" "${poll_attempts}"

  assert_success
  assert_line  "SCAN_NOT_PRESENT"

  unstub aws
}

@test "When scan result fetch fails, an error is returned" {
  local registry_id="012345678912"
  local repo_name="repo-name"
  local image_identifier="imageDigest=image-hash"
  local poll_attempts="1"

  scan_findings_base_args="--registry-id ${registry_id} --repository-name ${repo_name} --image-id ${image_identifier} --no-paginate"
  scan_findings_status="${scan_findings_base_args} --query imageScanStatus.status --output text"

  stub aws \
    "ecr describe-image-scan-findings ${scan_findings_status} : echo something went wrong; exit 1"

  run poll_ecr_scan_result "${registry_id}" "${repo_name}" "${image_identifier}" "${poll_attempts}"

  assert_success
  assert_line --partial "something went wrong"

  unstub aws
}

@test "When image is unsupported, it returns the status immediately" {
  local registry_id="012345678912"
  local repo_name="repo-name"
  local image_identifier="imageDigest=image-hash"
  local poll_attempts="1"

  scan_findings_base_args="--registry-id ${registry_id} --repository-name ${repo_name} --image-id ${image_identifier} --no-paginate"
  scan_findings_status="${scan_findings_base_args} --query imageScanStatus.status --output text"

  stub aws \
    "ecr describe-image-scan-findings ${scan_findings_status} : echo UNSUPPORTED_IMAGE"

  run poll_ecr_scan_result "${registry_id}" "${repo_name}" "${image_identifier}" "${poll_attempts}"

  assert_success
  assert_line  "UNSUPPORTED_IMAGE"

  unstub aws
}

@test "When AWS takes time to produce an image, it checks multiple times until the image is available and succeeds" {
  local registry_id="012345678912"
  local repo_name="repo-name"
  local image_identifier="imageDigest=image-hash"
  local poll_attempts="10"

  scan_findings_base_args="--registry-id ${registry_id} --repository-name ${repo_name} --image-id ${image_identifier} --no-paginate"
  scan_findings_status="${scan_findings_base_args} --query imageScanStatus.status --output text"

  stub aws \
    "ecr describe-image-scan-findings ${scan_findings_status} : echo IN_PROGRESS" \
    "ecr describe-image-scan-findings ${scan_findings_status} : echo PENDING" \
    "ecr describe-image-scan-findings ${scan_findings_status} : echo COMPLETE"

  stub sleep \
    '* : echo 1>&2 sleep $@' \
    '* : echo 1>&2 sleep $@' \
    '* : echo 1>&2 sleep $@'

  run poll_ecr_scan_result "${registry_id}" "${repo_name}" "${image_identifier}" "${poll_attempts}"

  assert_success
  assert_line  "COMPLETE"

  unstub aws
}
