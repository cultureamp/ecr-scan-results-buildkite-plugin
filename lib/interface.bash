#!/usr/bin/env bash

dir="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

# shellcheck source=lib/shared.bash
. "$dir/../lib/shared.bash"
# shellcheck source=lib/errors.bash
. "$dir/../lib/errors.bash"
# shellcheck source=lib/ecr.bash
. "$dir/../lib/ecr.bash"

function post_command {
  trap notify_error ERR

  # check all inputs exist and are valid
  image_name_pattern="^[0-9]{12}\.dkr\.ecr\.[a-z][a-z1-9-]+\.amazonaws.com/[^:]+:[^:]+$"
  count_pattern="^[0-9]+$"

  IMAGE_NAME="$(plugin_read_config "IMAGE_NAME")"
  MAX_CRITICALS="$(plugin_read_config "MAX_CRITICALS" "0")"
  MAX_HIGHS="$(plugin_read_config "MAX_HIGHS" "0")"
  IMAGE_LABEL="$(plugin_read_config "IMAGE_LABEL")"
  IMAGE_LABEL_APP="_${IMAGE_LABEL}"

  if [[ -z "${IMAGE_NAME}" || ! "${IMAGE_NAME}" =~ ${image_name_pattern} ]]; then
    configuration_error "No 'image-name' argument provided, or not in required format.
  Expected form is: AWS_ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/REPOSITORY_NAME:IMAGE_TAG
  with the text in capitals replaced with the appropriate values"
  fi

  if [[ ! "${MAX_CRITICALS}" =~ ${count_pattern} ]]
  then
    configuration_error "'max-criticals' argument must be a positive integer (when supplied)"
  fi

  if [[ ! "${MAX_HIGHS}" =~ ${count_pattern} ]]
  then
    configuration_error "'max-highs' argument must be a positive integer (when supplied)"
  fi

  if [[ ! "${IMAGE_LABEL}" =~ ^[a-z][a-z0-9]*$ ]]
  then
    configuration_error "'image-label' argument must be an alphanumeric string that starts with a letter (when supplied)"
  fi

  # print input values
  cat << EOM
Configuration:
    image-name:${IMAGE_NAME}"
    max-criticals=${MAX_CRITICALS}"
    max-highs=${MAX_HIGHS}"
    image-label=${IMAGE_LABEL}"

EOM

  FULL_REPO_NAME="${IMAGE_NAME%:*}"
  REPO_NAME="${FULL_REPO_NAME#*/}"
  IMAGE_TAG="${IMAGE_NAME#*:}"
  IFS="." read -ra dot_fields <<< "${IMAGE_NAME}"
  REPOSITORY_ID="${dot_fields[0]}"
  REGION="${dot_fields[3]}"

  cat << EOM
Derived inputs:
    FULL_REPO_NAME="${FULL_REPO_NAME}"
    REPO_NAME="${REPO_NAME}"
    IMAGE_TAG="${IMAGE_TAG}"
    REPOSITORY_ID="${REPOSITORY_ID}"
    REGION="${REGION}"

EOM

  # Translate an image tag to an image digest: this is more specific and reliable
  # than just using the image tag.
  echo "--- retrieving image digest"
  image_digest="$(get_ecr_image_digest "${REPOSITORY_ID}" "${REPO_NAME}" "${IMAGE_TAG}")"
  image_identifier="imageDigest=${image_digest}"
  echo "Using image digest: ${image_digest}"

  echo "--- waiting for scan results to be available..."
  scan_status="$(poll_ecr_scan_result "${REPOSITORY_ID}" "${REPO_NAME}" "${image_identifier}" "${POLL_ATTEMPTS:-"20"}")"

  if [[ "${scan_status}" == "UNSUPPORTED_IMAGE" ]]; then
    annotation=$(printf "Warning: ECR vulnerability scan does not support this image type (%s).\n\nThe \`ecr-scan-results\` plugin will not supply useful results for this image: \`%s\`" "${scan_status}" "${IMAGE_NAME}")
    soft_failure "${annotation}" "${IMAGE_LABEL}"
  elif [[ "${scan_status}" != "COMPLETE" && "${scan_status}" != "ACTIVE" ]]; then
    annotation=$(printf "ECR vulnerability scan failed with status: %s.\n\nVulnerability details not available." "${scan_status}")
    if [[ "${scan_status}" = "SCAN_NOT_PRESENT" ]]; then
        annotation=$(printf "No ECR vulnerability scan available for image: \`%s\`\n\nThe results may be taking some time to report, or there may be an issue with scan configuration." "${IMAGE_NAME}")
    fi
    soft_failure "${annotation}" "${IMAGE_LABEL}"
  fi

  echo "ECR scan complete."

  echo "--- querying results..."

  # retrieve counts of criticals and highs or fail build if scan failed
  criticals=$(aws ecr describe-image-scan-findings \
      --registry-id "${REPOSITORY_ID}" \
      --repository-name "${REPO_NAME}" \
      --image-id "${image_identifier}" \
      --no-paginate \
      --query "imageScanFindings.findingSeverityCounts.CRITICAL" \
      --output text)
  if [ "${criticals}" = "None" ]; then criticals="0"; fi

  highs=$(aws ecr describe-image-scan-findings \
      --registry-id "${REPOSITORY_ID}" \
      --repository-name "${REPO_NAME}" \
      --image-id "${image_identifier}" \
      --no-paginate \
      --query "imageScanFindings.findingSeverityCounts.HIGH" \
      --output text)
  if [ "${highs}" = "None" ]; then highs="0"; fi

  # report results
  vuln_url=$(printf "https://%s.console.aws.amazon.com/ecr/repositories/private/%s/%s/image/%s/scan-results/?region=%s" "${REGION}" "${REPOSITORY_ID}" "${REPO_NAME}" "${image_digest}" "${REGION}")

  image_label_header="#### Vulnerability summary"
  if [ -n "${IMAGE_LABEL}" ]
  then
      image_label_header=$(printf "#### Vulnerability summary for \"%s\"\n\n" "${IMAGE_LABEL}")
  fi

  annotation_style="info"

  # check if thresholds are exceeded and if so fail build
  fail_build="false"
  exceeded_criticals=""
  exceeded_highs=""

  if [ -n "${MAX_CRITICALS}" ] && [ "${criticals}" -gt "${MAX_CRITICALS}" ]
  then
      exceeded_criticals=$(printf "**exceeds threshold %d**" "${MAX_CRITICALS}")
      annotation_style="error"
      fail_build="true"
  fi

  if  [ -n "${MAX_HIGHS}" ] && [ "${highs}" -gt "${MAX_HIGHS}" ]
  then
      exceeded_highs=$(printf "**exceeds threshold %d**" "${MAX_HIGHS}")
      annotation_style="error"
      fail_build="true"
  fi

  annotation=$(cat << EOM
  ${image_label_header}

  - Critical: ${criticals} ${exceeded_criticals}
  - High: ${highs} ${exceeded_highs}

  <a href="${vuln_url}">Vulnerability details are available</a> in the AWS console. This link will work
  when logged into the appropriate AWS account (${REPOSITORY_ID}) with \`ecr:DescribeImages\`
  and \`ecr:DescribeImageScanFindings\` permissions.
EOM
  )

  buildkite-agent annotate --style "${annotation_style}" --context "vuln_counts${IMAGE_LABEL_APP}" "${annotation}"

  if  [ "${fail_build}" = "true" ]
  then
      exit 1
  fi
}
