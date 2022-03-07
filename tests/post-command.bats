#!/usr/bin/env bats

load '/usr/local/lib/bats/load.bash'
# shellcheck source=lib/interface.bash

#
# Simple top level tests to assure we're loading interface.bash
#

# Uncomment the following line to debug stub failures
# export [stub_command]_STUB_DEBUG=/dev/tty

@test "When I don't supply image-name, it fails with a helpful error message" {
  run "$PWD/hooks/post-command"

  assert_failure
  assert_line "No 'image-name' argument provided, or not in required format."
}
