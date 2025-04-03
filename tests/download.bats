#!/usr/bin/env bats

load "${BATS_PLUGIN_PATH}/load.bash"

load '../lib/download.bash'

sleep_stub_command='echo sleep $@'
sleep_stubs=("$sleep_stub_command" "$sleep_stub_command" "$sleep_stub_command" "$sleep_stub_command" "$sleep_stub_command")


#
# Tests for top-level docker bootstrap command. The rest of the plugin runs in Go.
#

# Uncomment the following line to debug stub failures
# export [stub_command]_STUB_DEBUG=/dev/tty
#export SLEEP_STUB_DEBUG=/dev/tty

setup() {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_BUILDKITE_PLUGIN_TEST_MODE=true
}

teardown() {
    unset BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_BUILDKITE_PLUGIN_TEST_MODE
    unstub curl || true
    unstub sleep || true
    rm ./ecr-scan-results-buildkite-plugin || true
}

create_script() {
cat > "$1" << EOM
set -euo pipefail

echo "executing $1:\$@"

EOM
}

@test "Downloads and runs the command for the current architecture" {

  function downloader() {
    echo "$@";
    create_script $2
  }
  export -f downloader

  run download_binary_and_run

  unset downloader

  assert_success
  assert_line --regexp "https://github.com/cultureamp/ecr-scan-results-buildkite-plugin/releases/latest/download/ecr-scan-results-buildkite-plugin_linux_amd64 ecr-scan-results-buildkite-plugin"
  assert_line --regexp "executing ecr-scan-results-buildkite-plugin"
}

@test "Attempts to download and succeed after 2 tries" {

  # Fails for first 2 tries and passes on later 

  stub curl \
      "echo 'curl 1 - Could not resolve host' && exit 6" \
      "echo 'curl 2 - Failed to connect to example.com port 80 - Connection refused' && exit 7" \
      "echo 'curl 3 - Success' && exit 0"

  stub sleep "${sleep_stubs[@]}"
  is_stubbed=true

  # executes the retry download command
  run retry_download "https://example.com" "$TMPDIR/output-plugin" "curl"

  
  assert_success
  assert_line --partial "Attempt 1"
  assert_line --partial "Attempt 2"
  assert_line --partial "Success"
}

@test "Attempts to download and fails after maximum tries" {

  # Fails for all 5 (maximum) tries 

  stub curl \
        "echo 'curl 1 - Could not resolve host: example.com' && exit 6" \
        "echo 'curl 2 (7) Failed to connect to example.com port 80 - Connection refused' && exit 7" \
        "echo 'curl 3 (7) Failed to connect to example.com port 80 - Connection refused' && exit 7"  \
        "echo 'curl 4 (7) Failed to connect to example.com port 80 - Connection refused' && exit 7"  \
        "echo 'curl 5 (7) Failed to connect to example.com port 80 - Connection refused' && exit 7"  \

  stub sleep "${sleep_stubs[@]}"
  is_stubbed=true

  # executes the retry download command
  run retry_download "https://example.com" "$TMPDIR/output-plugin" "curl"

  assert_failure
  # Checks if multiple attempts are made to retry the download
  assert_line --partial "Download failed after 5 attempts" 
}