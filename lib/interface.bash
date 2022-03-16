#!/usr/bin/env bash
set -euo pipefail

dir="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

# shellcheck source=lib/shared.bash
. "$dir/../lib/shared.bash"
# shellcheck source=lib/errors.bash
. "$dir/../lib/errors.bash"
# shellcheck source=lib/ecr.bash
. "$dir/../lib/ecr.bash"
# shellcheck source=lib/results.bash
. "$dir/../lib/results.bash"

function post_command {
  # trap notify_error ERR

  # check all inputs exist and are valid
  local image_name_pattern="^[0-9]{12}\.dkr\.ecr\.[a-z][a-z1-9-]+\.amazonaws.com/[^:]+:[^:]+$"
  local count_pattern="^[0-9]+$"

  local image_name; image_name="$(plugin_read_config "IMAGE_NAME")"
  local max_criticals; max_criticals="$(plugin_read_config "MAX_CRITICALS" "0")"
  local max_highs; max_highs="$(plugin_read_config "MAX_HIGHS" "0")"
  local image_label; image_label="$(plugin_read_config "IMAGE_LABEL")"
  local image_label_app="_${image_label}"
echo "image_label: ${image_label}"
  # allow for override in testing
  local poll_attempts="${POLL_ATTEMPTS:-"20"}"

  if [[ -z "${image_name}" || ! "${image_name}" =~ ${image_name_pattern} ]]; then
    configuration_error "No 'image-name' argument provided, or not in required format.
  Expected form is: AWS_ACCOUNT_ID.dkr.ecr.REGION.amazonaws.com/REPOSITORY_NAME:IMAGE_TAG
  with the text in capitals replaced with the appropriate values"
  fi

  if [[ ! "${max_criticals}" =~ ${count_pattern} ]]
  then
    configuration_error "'max-criticals' argument must be a positive integer (when supplied)"
  fi

  if [[ ! "${max_highs}" =~ ${count_pattern} ]]
  then
    configuration_error "'max-highs' argument must be a positive integer (when supplied)"
  fi

  if [[ -n "${image_label}" && ! "${image_label}" =~ ^[a-z][a-z0-9_-]*$ ]]
  then
    configuration_error "'image-label' argument must be an alphanumeric string that starts with a letter (when supplied)"
  fi

  # print input values
  cat << EOM
Configuration:
    image-name:${image_name}"
    max-criticals=${max_criticals}"
    max-highs=${max_highs}"
    image-label=${image_label}"

EOM

  full_repo_name="${image_name%:*}"
  repo_name="${full_repo_name#*/}"
  image_tag="${image_name#*:}"
  IFS="." read -ra dot_fields <<< "${image_name}"
  repository_id="${dot_fields[0]}"
  region="${dot_fields[3]}"

  cat << EOM
Derived inputs:
    full_repo_name="${full_repo_name}"
    repo_name="${repo_name}"
    image_tag="${image_tag}"
    repository_id="${repository_id}"
    region="${region}"

EOM

  # Translate an image tag to an image digest: this is more specific and reliable
  # than just using the image tag.
  echo "--- retrieving image digest"
#  aws ecr describe-images \
#         --registry-id "${repository_id}" \
#         --repository-name "${repo_name}" \
#         --image-id imageTag="${image_tag}" \
#         --query "imageDetails[0].imageDigest" \
#         --output text

# get_ecr_image_digest "${repository_id}" "${repo_name}" "${image_tag}"

  image_digest="$( get_ecr_image_digest "${repository_id}" "${repo_name}" "${image_tag}" )"
  image_identifier="imageDigest=${image_digest}"
  echo "Using image digest: ${image_digest}"

  # Wait for the scan to be ready. Depending on the type of scanning active, the
  # result may be "COMPLETE" or "ACTIVE".
  echo "--- waiting for scan results to be available..."
  scan_status="$(poll_ecr_scan_result "${repository_id}" "${repo_name}" "${image_identifier}" "${poll_attempts}")"

  if [[ "${scan_status}" == "UNSUPPORTED_IMAGE" ]]; then
    annotation=$(printf "Warning: ECR vulnerability scan does not support this image type (%s).\n\nThe \`ecr-scan-results\` plugin will not supply useful results for this image: \`%s\`" "${scan_status}" "${image_name}")
    soft_failure "${annotation}" "${image_label}"
  elif [[ "${scan_status}" != "COMPLETE" && "${scan_status}" != "ACTIVE" ]]; then
    annotation=$(printf "ECR vulnerability scan failed with status: %s.\n\nVulnerability details not available." "${scan_status}")
    if [[ "${scan_status}" = "SCAN_NOT_PRESENT" ]]; then
        annotation=$(printf "No ECR vulnerability scan available for image: \`%s\`\n\nThe results may be taking some time to report, or there may be an issue with scan configuration." "${image_name}")
    fi
    soft_failure "${annotation}" "${image_label}"
  fi

  echo "ECR scan complete."

  echo "--- querying results..."

  # Query the results and save in a local temp file
  local scan_results_file; scan_results_file="$(write_scan_results  "${repository_id}" "${repo_name}" "${image_identifier}")"

  echo "${scan_results_file}"

  criticals=0
  highs=0

  # report results
  vuln_url=$(printf "https://%s.console.aws.amazon.com/ecr/repositories/private/%s/%s/image/%s/scan-results/?region=%s" "${region}" "${repository_id}" "${repo_name}" "${image_digest}" "${region}")

  image_label_header="#### Vulnerability summary"
  if [ -n "${image_label}" ]
  then
      image_label_header=$(printf "#### Vulnerability summary for \"%s\"\n\n" "${image_label}")
  fi

  annotation_style="info"

  # check if thresholds are exceeded and if so fail build
  fail_build="false"
  exceeded_criticals=""
  exceeded_highs=""

  if [ -n "${max_criticals}" ] && [ "${criticals}" -gt "${max_criticals}" ]
  then
      exceeded_criticals=$(printf "**exceeds threshold %d**" "${max_criticals}")
      annotation_style="error"
      fail_build="true"
  fi

  if  [ -n "${max_highs}" ] && [ "${highs}" -gt "${max_highs}" ]
  then
      exceeded_highs=$(printf "**exceeds threshold %d**" "${max_highs}")
      annotation_style="error"
      fail_build="true"
  fi

  annotation=$(cat << EOM
  ${image_label_header}

  - Critical: ${criticals} ${exceeded_criticals}
  - High: ${highs} ${exceeded_highs}

  <a href="${vuln_url}">Vulnerability details are available</a> in the AWS console. This link will work
  when logged into the appropriate AWS account (${repository_id}) with \`ecr:DescribeImages\`
  and \`ecr:DescribeImageScanFindings\` permissions.
EOM
  )

  buildkite-agent annotate --style "${annotation_style}" --context "vuln_counts${image_label_app}" "${annotation}"

  if  [ "${fail_build}" = "true" ]
  then
      exit 1
  fi
}
