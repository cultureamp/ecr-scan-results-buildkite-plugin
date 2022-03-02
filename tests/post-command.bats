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

# @test "Runs go list and Nancy" {
#   # export BUILDKITE_PLUGIN_SONATYPE_NANCY_GO_VERSION=""

#   stub docker \
#     'pull * : echo $@' \
#     'pull * : echo $@' \
#     'run * : echo $@' \
#     'run * : echo $@'

#   run "$PWD/hooks/command"

#   unstub docker

#   expected_go_image="1-alpine"

#   assert_success
#   assert_line --regexp "run --rm -it .* golang:${expected_go_image} go list -json -m all"
#   assert_line --regexp "run --rm -i .* sonatypecommunity/nancy:latest sleuth"
# }

# @test "Runs with the latest version of Go by default" {
#   # export BUILDKITE_PLUGIN_SONATYPE_NANCY_GO_VERSION=""

#   stub docker \
#     'pull * : echo $@' \
#     'pull * : echo $@' \
#     'run * : echo $@' \
#     'run * : echo $@'

#   run "$PWD/hooks/command"

#   unstub docker

#   expected_go_image="1-alpine"

#   assert_success
#   assert_line --partial "pull golang:${expected_go_image}"
#   assert_line --regexp "run.+ golang:${expected_go_image} go list -json -m all"
# }

# @test "Uses Alpine Go image unless forced" {
#   export BUILDKITE_PLUGIN_SONATYPE_NANCY_GO_VERSION="1.17"

#   stub docker \
#     'pull * : echo $@' \
#     'pull * : echo $@' \
#     'run * : echo $@' \
#     'run * : echo $@'

#   run "$PWD/hooks/command"

#   unstub docker

#   expected_go_image="1.17-alpine"

#   assert_success
#   assert_line --partial "pull golang:${expected_go_image}"
#   assert_line --regexp "run.+ golang:${expected_go_image} go list -json -m all"
# }

# @test "Uses specific Go image when supplied" {
#   export BUILDKITE_PLUGIN_SONATYPE_NANCY_GO_VERSION="1.17-bullseye"

#   stub docker \
#     'pull * : echo $@' \
#     'pull * : echo $@' \
#     'run * : echo $@' \
#     'run * : echo $@'

#   run "$PWD/hooks/command"

#   unstub docker

#   expected_go_image="1.17-bullseye"

#   assert_success
#   assert_line --partial "pull golang:${expected_go_image}"
#   assert_line --regexp "run.+ golang:${expected_go_image} go list -json -m all"
# }

# @test "Uses current directory when no working directory is supplied" {
#   export BUILDKITE_PLUGIN_SONATYPE_NANCY_WORKING_DIRECTORY=""

#   stub docker \
#     'pull * : echo $@' \
#     'pull * : echo $@' \
#     'run * : echo $@' \
#     'run * : echo $@'

#   run "$PWD/hooks/command"

#   unstub docker

#   expected_work_dir="/plugin"

#   assert_success
#   assert_line --regexp "run.* -it -v ${expected_work_dir}:/app -w /app golang:"
#   assert_line --regexp "run.* -i -v ${expected_work_dir}:/app -w /app sonatypecommunity/nancy:"
# }

# @test "Mounts correct working directory when supplied" {
#   export BUILDKITE_PLUGIN_SONATYPE_NANCY_WORKING_DIRECTORY="hooks"

#   stub docker \
#     'pull * : echo $@' \
#     'pull * : echo $@' \
#     'run * : echo $@' \
#     'run * : echo $@'

#   run "$PWD/hooks/command"

#   expected_work_dir="/plugin/hooks"

#   assert_success
#   assert_line --regexp "run.* -it -v ${expected_work_dir}:/app -w /app golang:"
#   assert_line --regexp "run.* -i -v ${expected_work_dir}:/app -w /app sonatypecommunity/nancy:"

#   unstub docker
# }
