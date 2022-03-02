#!/usr/bin/env bash

plugin_prefix="BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_"

# Shorthand for reading env config
function plugin_read_config() {
  local var="${plugin_prefix}${1}"
  local default="${2:-}"
  echo "${!var:-$default}"
}

# Reads either a value or a list from plugin config
function plugin_read_list() {
  prefix_read_list "${plugin_prefix}${1}"
}

# Reads either a value or a list from the given env prefix
function prefix_read_list() {
  local prefix="${1}"
  local parameter="${prefix}_0"

  if [[ -n "${!parameter:-}" ]]; then
    local i=0
    local parameter="${prefix}_${i}"
    while [[ -n "${!parameter:-}" ]]; do
      echo "${!parameter}"
      i=$((i+1))
      parameter="${prefix}_${i}"
    done
  elif [[ -n "${!prefix:-}" ]]; then
    echo "${!prefix}"
  fi
}
