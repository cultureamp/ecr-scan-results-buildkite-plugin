#!/usr/bin/env bats

load "${BATS_PLUGIN_PATH}/load.bash"

#
# Tests for pre-command hook
#

# Uncomment the following line to debug stub failures
# export [stub_command]_STUB_DEBUG=/dev/tty
#export DOCKER_STUB_DEBUG=/dev/tty

setup() {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_BUILDKITE_PLUGIN_HOOK_TEST_MODE=true
}

teardown() {
  unset BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_BUILDKITE_PLUGIN_HOOK_TEST_MODE
  unset BUILDKITE_COMMAND_EXIT_STATUS
}

@test "Executes scan when command has succeeded" {
  export BUILDKITE_COMMAND_EXIT_STATUS=0
  run "$PWD/hooks/post-command"

  assert_success
  assert_line --partial "TEST: executing download"
}

@test "Executes scan when command result not present" {
  run "$PWD/hooks/post-command"

  assert_success
  assert_line --partial "TEST: executing download"
}

@test "Skips execution when build fails" {
  export BUILDKITE_COMMAND_EXIT_STATUS=12
  run "$PWD/hooks/post-command"

  assert_success
  assert_line --partial "skipping ECR scan check"
}
