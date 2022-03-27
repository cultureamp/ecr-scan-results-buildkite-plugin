#!/usr/bin/env bash
set -euo pipefail

dir="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

# shellcheck source=lib/shared.bash
. "$dir/../lib/shared.bash"

function post_command {

  # find the plugin version in use - this will be used as the tag for the runtime image that will be pulled
  plugin_name="github.com/cultureamp/ecr-scan-results-buildkite-plugin"
  version_query=". | map_values(keys) | flatten | map(select(startswith(\"$plugin_name\"))) | first | split(\"#\") | .[1]"
  plugin_version="$(jq --raw-output "$version_query" <<<"$BUILDKITE_PLUGINS")"

  if [[ "$plugin_version" = "null" ]]; then
    echo "🚨 no plugin version found, using tag 'latest'"
    plugin_version="latest"
  fi

  runtime_image="cultureampci/ecr-scan-results-buildkite-plugin:${plugin_version}"

  echo "Pulling ECR scan results runtime image ($plugin_version) .."
  docker pull "${runtime_image}"

  echo "Running ECR scan results runtime image ($plugin_version) ..."
  args=(--rm -it)

  # Mount the buildkite agent into the container
  if [[ -z "${BUILDKITE_AGENT_BINARY_PATH:-}" ]] ; then
    if ! command -v buildkite-agent >/dev/null 2>&1 ; then
      echo -n "🚨 Failed to find buildkite-agent in PATH to mount into container, "
      echo "you can disable this behaviour with 'mount-buildkite-agent:false'"
    else
      BUILDKITE_AGENT_BINARY_PATH=$(command -v buildkite-agent)
    fi
  fi

  # Mount buildkite-agent if we have a path for it
  if [[ -n "${BUILDKITE_AGENT_BINARY_PATH:-}" ]] ; then
    args+=(
      "--env" "BUILDKITE_JOB_ID"
      "--env" "BUILDKITE_BUILD_ID"
      "--env" "BUILDKITE_AGENT_ACCESS_TOKEN"
      "--volume" "$BUILDKITE_AGENT_BINARY_PATH:/usr/bin/buildkite-agent"
    )
  fi

  # Propagate all environment variables into the container
  if [[ -n "${BUILDKITE_ENV_FILE:-}" ]] ; then
    # Read in the env file and convert to --env params for docker
    # This is because --env-file doesn't support newlines or quotes per https://docs.docker.com/compose/env-file/#syntax-rules
    while read -r var; do
      args+=( --env "${var%%=*}" )
    done < "$BUILDKITE_ENV_FILE"
  else
    echo "🚨 Not propagating environment variables to container as \$BUILDKITE_ENV_FILE is not set"
  fi

  # Propagate aws auth environment variables into the container e.g. from assume role plugins
  if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]] ; then
    args+=( --env "AWS_ACCESS_KEY_ID" )
  fi
  if [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]] ; then
    args+=( --env "AWS_SECRET_ACCESS_KEY" )
  fi
  if [[ -n "${AWS_SESSION_TOKEN:-}" ]] ; then
    args+=( --env "AWS_SESSION_TOKEN" )
  fi
  if [[ -n "${AWS_REGION:-}" ]] ; then
    args+=( --env "AWS_REGION" )
  fi
  if [[ -n "${AWS_DEFAULT_REGION:-}" ]] ; then
    args+=( --env "AWS_DEFAULT_REGION" )
  fi

  # pass the plugin arguments
  args+=( --env "BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME" )

  args+=("$runtime_image")

  echo "Running plugin in ${runtime_image}, command:"
  echo -ne '\033[90m$\033[0m docker run ' >&2

  # Print all the arguments, with a space after, properly shell quoted
  printf "%q " "${args[@]}"
  echo

  docker run "${args[@]}"
}
