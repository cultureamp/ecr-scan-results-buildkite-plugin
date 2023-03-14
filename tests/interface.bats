#!/usr/bin/env bats

load '/usr/local/lib/bats/load.bash'
# shellcheck source=lib/interface.bash
load '../lib/interface'

#
# Tests for top-level docker bootstrap command. The rest of the plugin runs in Go.
#

# Uncomment the following line to debug stub failures
# export [stub_command]_STUB_DEBUG=/dev/tty
#export DOCKER_STUB_DEBUG=/dev/tty

@test "When no configuration is supplied, it runs docker with the latest image" {
  stub docker \
    ':: echo stubbed docker $@' \
    ':: echo stubbed docker $@'
  run post_command

  assert_success
  assert_line --partial "stubbed docker pull cultureampci/ecr-scan-results-buildkite-plugin:latest"
  assert_line --regexp "stubbed docker run .* cultureampci/ecr-scan-results-buildkite-plugin:latest"

  unstub docker
}

@test "When plugin configuration is supplied, it runs docker with the configured version"  {
  export BUILDKITE_PLUGINS="[{\"github.com/buildkite-plugins/ecr-buildkite-plugin#v1.2.0\":{\"login\":true,\"account_ids\":\"0123456789\"}},{\"github.com/cultureamp/ecr-scan-results-buildkite-plugin#version1\":{\"image-name\":\"0123456789.dkr.ecr.us-west-2.amazonaws.com/master/web-gateway/ecs:build-2801\",\"image-label\":\"web-gateway\"}}]"
  stub docker \
    ':: echo stubbed docker $@' \
    ':: echo stubbed docker $@'
  run post_command

  assert_success
  assert_line --partial "stubbed docker pull cultureampci/ecr-scan-results-buildkite-plugin:version1"
  assert_line --regexp "stubbed docker run .* cultureampci/ecr-scan-results-buildkite-plugin:version1"

  unstub docker
}


@test "When multiple plugin configurations are supplied, it runs docker with the first configured version"  {
  export BUILDKITE_PLUGINS="[{\"github.com/buildkite-plugins/ecr-buildkite-plugin#v1.2.0\":{\"login\":true,\"account_ids\":\"0123456789\"}},{\"github.com/cultureamp/ecr-scan-results-buildkite-plugin#version0\":{\"image-name\":\"0123456789.dkr.ecr.us-west-2.amazonaws.com/master/web-gateway/ecs:build-2801\",\"image-label\":\"web-gateway\"}},{\"github.com/cultureamp/ecr-scan-results-buildkite-plugin#version1\":{\"image-name\":\"0123456789.dkr.ecr.us-west-2.amazonaws.com/master/web-gateway/ecs:build-2801\",\"image-label\":\"web-gateway\"}}]"
  stub docker \
    ':: echo stubbed docker $@' \
    ':: echo stubbed docker $@'
  run post_command

  assert_success
  assert_line --partial "stubbed docker pull cultureampci/ecr-scan-results-buildkite-plugin:version0"
  assert_line --regexp "stubbed docker run .* cultureampci/ecr-scan-results-buildkite-plugin:version0"

  unstub docker
}

@test "When no plugin parameters are supplied, no parameters are passed to the docker run command"  {
  stub docker \
    ':: echo stubbed docker $@' \
    ':: echo stubbed docker $@'

  run post_command

  assert_success
  refute_line --partial "BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_"

  unstub docker
}

@test "When plugin parameters are supplied, they are passed to the docker run command"  {
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_ONE="one"
  export BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_TWO="two"

  stub docker \
    ':: echo stubbed docker $@' \
    ':: echo stubbed docker $@'

  run post_command

  assert_success
  assert_line --partial "--env BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_ONE"
  assert_line --partial "--env BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_TWO"

  unstub docker
}

@test "When AWS variables are present, they are passed to the docker run command"  {
  export AWS_ACCESS_KEY_ID="val"
  export AWS_SECRET_ACCESS_KEY="val"
  export AWS_SESSION_TOKEN="val"
  export AWS_REGION="val"
  export AWS_DEFAULT_REGION="val"

  stub docker \
    ':: echo stubbed docker $@' \
    ':: echo stubbed docker $@'

  run post_command

  assert_success
  assert_line --partial "--env AWS_ACCESS_KEY_ID"
  assert_line --partial "--env AWS_SECRET_ACCESS_KEY"
  assert_line --partial "--env AWS_SESSION_TOKEN"
  assert_line --partial "--env AWS_REGION"
  assert_line --partial "--env AWS_DEFAULT_REGION"

  unstub docker
}

@test "When buildkite-agent is present, it is mounted into the Docker environment"  {
  export BUILDKITE_AGENT_BINARY_PATH="/bin/buildkite-agent"

  stub docker \
    ':: echo stubbed docker $@' \
    ':: echo stubbed docker $@'

  run post_command

  assert_success
  assert_line --partial "--env BUILDKITE_AGENT_ACCESS_TOKEN "
  assert_line --partial "--env BUILDKITE_BUILD_ID "
  assert_line --partial "--env BUILDKITE_JOB_ID "
  assert_line --partial "--volume /bin/buildkite-agent:/usr/bin/buildkite-agent"

  unstub docker
}

@test "When Buildkite env file is present, its contents are passed to the docker run command"  {
  export BUILDKITE_ENV_FILE="${BATS_TEST_DIRNAME}/fixtures/buildkite-test.env"

  stub docker \
    ':: echo stubbed docker $@' \
    ':: echo stubbed docker $@'

  run post_command

  assert_success
  assert_line --partial "--env VARIABLE_ONE "
  assert_line --partial "--env VARIABLE_ONE "

  unstub docker
}
