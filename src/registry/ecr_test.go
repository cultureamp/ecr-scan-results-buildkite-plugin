package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/smithy-go"
	"github.com/hexops/autogold/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryInfoFromURLSucceeds(t *testing.T) {
	cases := []struct {
		test     string
		url      string
		expected autogold.Value
	}{
		{
			test: "Url with label",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo:latest",
			expected: autogold.Expect(ImageReference{
				RegistryID: "123456789012", Region: "us-west-2",
				Name: "test-repo",
				Tag:  "latest",
			}),
		},
		{
			test: "Url with digest",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo@sha256:hash",
			expected: autogold.Expect(ImageReference{
				RegistryID: "123456789012", Region: "us-west-2",
				Name:   "test-repo",
				Digest: "sha256:hash",
			}),
		},
		{
			test: "Url with tag and digest",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo:tagged@sha256:hash",
			expected: autogold.Expect(ImageReference{
				RegistryID: "123456789012", Region: "us-west-2",
				Name: "test-repo",
				Tag:  "tagged@sha256:hash",
			}),
		},
		{
			test: "Url without label",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo",
			expected: autogold.Expect(ImageReference{
				RegistryID: "123456789012", Region: "us-west-2",
				Name: "test-repo",
			}),
		},
	}

	for _, c := range cases {
		t.Run(c.test, func(t *testing.T) {
			info, err := ParseReferenceFromURL(c.url)
			require.NoError(t, err)
			c.expected.Equal(t, info)
		})
	}
}

func TestRegistryInfoFromURLFails(t *testing.T) {
	url := "123456789012.dkr.ecr.us-west-2.amazonaws.com"

	info, err := ParseReferenceFromURL(url)
	require.ErrorContains(t, err, "invalid registry URL")

	assert.Equal(t, ImageReference{}, info)
}

func TestScanStateRetryableOnNotFound(t *testing.T) {
	setupRetryTest := func(wrappedReturnValue bool, wrappedError error) (func(*testing.T, bool), RetryPolicyFunc) {
		wrappedCalled := false
		wrapped := func(ctx context.Context, input *ecr.DescribeImageScanFindingsInput, output *ecr.DescribeImageScanFindingsOutput, err error) (bool, error) {
			wrappedCalled = true
			return wrappedReturnValue, wrappedError
		}

		retry := scanStateRetryableOnNotFound(wrapped)
		return func(t *testing.T, expected bool) {
			t.Helper()
			assert.Equal(t, expected, wrappedCalled, "Calling wrapped function: expected %t but was %t", expected, wrappedCalled)
		}, retry
	}

	t.Run("Returns true for ScanNotFoundException", func(t *testing.T) {
		assertCalled, retry := setupRetryTest(false, nil)

		scanNotFoundErr := &smithy.GenericAPIError{
			Code:    "ScanNotFoundException",
			Message: "Scan not found",
		}

		shouldRetry, err := retry(t.Context(), nil, nil, scanNotFoundErr)

		assert.True(t, shouldRetry, "Should retry on ScanNotFoundException")
		require.NoError(t, err, "Should not return an error")
		assertCalled(t, false)
	})

	t.Run("Delegates to wrapped function for other API errors", func(t *testing.T) {
		assertWrapped, retry := setupRetryTest(true, errors.New("wrapped error"))

		otherErr := &smithy.GenericAPIError{
			Code:    "OtherError",
			Message: "Some other error",
		}

		shouldRetry, err := retry(t.Context(), nil, nil, otherErr)

		assert.True(t, shouldRetry, "Should return wrapped function's retry decision")
		require.EqualError(t, err, "wrapped error", "Should return wrapped function's error")
		assertWrapped(t, true)
	})

	t.Run("Delegates to wrapped function for non-API errors", func(t *testing.T) {
		assertWrapped, retry := setupRetryTest(false, nil)

		nonAPIErr := errors.New("non-API error")

		shouldRetry, err := retry(t.Context(), nil, nil, nonAPIErr)

		assert.False(t, shouldRetry, "Should return wrapped function's retry decision")
		require.NoError(t, err, "Should return wrapped function's error")
		assertWrapped(t, true)
	})
}
