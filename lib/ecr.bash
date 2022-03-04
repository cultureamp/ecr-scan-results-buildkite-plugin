#!/usr/bin/env bash

function get_ecr_image_digest {
  local repository_id="${1}"
  local repo_name="${2}"
  local image_tag="${3}"

  local image_digest

  image_digest=$(aws ecr describe-images \
        --registry-id "${repository_id}" \
        --repository-name "${repo_name}" \
        --image-id imageTag="${image_tag}" \
        --query "imageDetails[0].imageDigest" \
        --output text)

  echo "${image_digest}"
}

function poll_ecr_scan_result {
  local repository_id="${1}"
  local repo_name="${2}"
  local image_identifier="${3}"
  local poll_attempts=${4:-"20"}

  # seconds to wait between attempts
  local poll_wait=3

  # poll until scan is COMPLETE or FAILED
  scan_status="SCAN_NOT_PRESENT"
  i="1"
  while [[ "${scan_status}" = "SCAN_NOT_PRESENT" || "${scan_status}" = "IN_PROGRESS" || "${scan_status}" = "PENDING" ]]  && [ "$i" -le "${poll_attempts}" ]
  do
      echo 1>&2 "Poll attempt ${i}..."
      if ! scan_status="$(aws ecr describe-image-scan-findings \
          --registry-id "${repository_id}" \
          --repository-name "${repo_name}" \
          --image-id "${image_identifier}" \
          --no-paginate \
          --query "imageScanStatus.status" \
          --output text 2>&1)"; then

          if grep -q "ScanNotFoundException" <<<"$scan_status"; then
              # if the scan isn't found, give it some more time to find the result
              scan_status="SCAN_NOT_PRESENT"
          else
              echo 1>&2 "${scan_status}"
              notify_error
          fi
      fi

      echo 1>&2 "scan status: ${scan_status}"

      # Give some time for the results to be available
      [ "$i" != "0" ] && sleep "${poll_wait}"

      ((i=i+1))
  done

  echo "${scan_status}"
}

