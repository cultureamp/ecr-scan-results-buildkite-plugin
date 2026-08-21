package main

import (
	"testing"

	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigParsing(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		setRequiredEnv(t)

		var c Config
		require.NoError(t, envconfig.Process("", &c))

		assert.False(t, c.FailBuildOnPluginFailure)
	})

	t.Run("reads Buildkite-prefixed plugin configuration", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_FAIL_BUILD_ON_PLUGIN_FAILURE", "true")

		var c Config
		require.NoError(t, envconfig.Process("", &c))

		assert.True(t, c.FailBuildOnPluginFailure)
	})
}

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BUILDKITE_JOB_ID", "job-id")
	t.Setenv("BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME", "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo:latest")
}
