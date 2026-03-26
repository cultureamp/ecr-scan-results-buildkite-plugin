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

func setupRetryTest(wrappedReturnValue bool, wrappedError error, retryPolicyFunc ...func(wrapped RetryPolicyFunc) RetryPolicyFunc) (func(*testing.T, bool), RetryPolicyFunc) {
	wrappedCalled := false
	opts := ecr.ImageScanCompleteWaiterOptions{}
	opts.Retryable = func(_ context.Context, _ *ecr.DescribeImageScanFindingsInput, _ *ecr.DescribeImageScanFindingsOutput, _ error) (bool, error) {
		wrappedCalled = true
		return wrappedReturnValue, wrappedError
	}
	withRetryPolicy(retryPolicyFunc...)(&opts)


	return func(t *testing.T, expected bool) {
		t.Helper()
		assert.Equal(t, expected, wrappedCalled, "Calling wrapped function: expected %t but was %t", expected, wrappedCalled)
	}, opts.Retryable
}

func TestRetryOnScanNotFound(t *testing.T) {
	t.Run("Returns true for ScanNotFoundException", func(t *testing.T) {
		assertCalled, retry := setupRetryTest(false, nil, retryOnScanNotFound)

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
		assertWrapped, retry := setupRetryTest(true, errors.New("wrapped error"), retryOnScanNotFound)

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
		assertWrapped, retry := setupRetryTest(false, nil, retryOnScanNotFound)

		nonAPIErr := errors.New("non-API error")

		shouldRetry, err := retry(t.Context(), nil, nil, nonAPIErr)

		assert.False(t, shouldRetry, "Should return wrapped function's retry decision")
		require.NoError(t, err, "Should return wrapped function's error")
		assertWrapped(t, true)
	})

	t.Run("Works well with others: ScanNotFoundException retries even when fastFailOnAccessDenied is in the chain", func(t *testing.T) {
		assertWrapped, retry := setupRetryTest(false, nil, fastFailOnAccessDenied, retryOnScanNotFound)

		scanNotFoundErr := &smithy.GenericAPIError{
			Code:    "ScanNotFoundException",
			Message: "Scan not found",
		}

		shouldRetry, err := retry(t.Context(), nil, nil, scanNotFoundErr)

		assert.True(t, shouldRetry, "Should retry on ScanNotFoundException")
		require.NoError(t, err, "Should not return an error")
		assertWrapped(t, false) // retryOnScanNotFound short-circuits before reaching wrapped
	})
}

func TestIsRetryableError(t *testing.T) {
	t.Run("Returns false for nil error", func(t *testing.T) {
		result := isRetryableError(nil)
		assert.False(t, result, "Should return false for nil error")
	})

	t.Run("Returns false for non-retryable API error codes", func(t *testing.T) {
		nonRetryableCodes := []string{
			"AccessDeniedException",
			"ValidationException",
			"InvalidParameterException",
		}

		for _, code := range nonRetryableCodes {
			t.Run(code, func(t *testing.T) {
				apiErr := &smithy.GenericAPIError{
					Code:    code,
					Message: "Non-retryable error",
				}
				result := isRetryableError(apiErr)
				assert.False(t, result, "Should return false for %s", code)
			})
		}
	})

	t.Run("Returns true for explicitly retryable API error codes", func(t *testing.T) {
		retryableCodes := []string{
			"ThrottlingException",
			"ServiceUnavailableException",
			"InternalServerError",
			"RequestTimeout",
			"RequestThrottled",
			"TooManyRequestsException",
			"InternalFailure",
			"Throttling",
			"ImageNotFoundException",
			"ResourceNotFoundException",
		}

		for _, code := range retryableCodes {
			t.Run(code, func(t *testing.T) {
				apiErr := &smithy.GenericAPIError{
					Code:    code,
					Message: "Retryable error",
				}
				result := isRetryableError(apiErr)
				assert.True(t, result, "Should return true for %s", code)
			})
		}
	})

	t.Run("Returns true for server fault API errors", func(t *testing.T) {
		apiErr := &smithy.GenericAPIError{
			Code:    "SomeServerError",
			Message: "Some server error",
			Fault:   smithy.FaultServer,
		}
		result := isRetryableError(apiErr)
		assert.True(t, result, "Should return true for server fault errors")
	})

	t.Run("Returns false for client fault API errors", func(t *testing.T) {
		apiErr := &smithy.GenericAPIError{
			Code:    "SomeClientError",
			Message: "Some client error",
			Fault:   smithy.FaultClient,
		}
		result := isRetryableError(apiErr)
		assert.False(t, result, "Should return false for client fault errors")
	})

	t.Run("Returns false for context deadline exceeded", func(t *testing.T) {
		result := isRetryableError(context.DeadlineExceeded)
		assert.False(t, result, "Should return false for context.DeadlineExceeded")
	})

	t.Run("Returns false for context canceled", func(t *testing.T) {
		result := isRetryableError(context.Canceled)
		assert.False(t, result, "Should return false for context.Canceled")
	})

	t.Run("Returns true for other error types", func(t *testing.T) {
		otherErr := errors.New("some other error")
		result := isRetryableError(otherErr)
		assert.True(t, result, "Should return true for other error types")
	})
}

func TestWithRetryPolicy(t *testing.T) {
	t.Run("Policies execute in listed order: first policy sees errors first", func(t *testing.T) {
		// fastFailOnAccessDenied is listed first, so it must execute first and
		// short-circuit before retryOnScanNotFound is reached.
		opts := ecr.ImageScanCompleteWaiterOptions{}
		opts.Retryable = func(_ context.Context, _ *ecr.DescribeImageScanFindingsInput, _ *ecr.DescribeImageScanFindingsOutput, _ error) (bool, error) {
			return true, nil
		}

		withRetryPolicy(fastFailOnAccessDenied, retryOnScanNotFound)(&opts)

		accessDeniedErr := errors.New("AccessDeniedException")
		shouldRetry, err := opts.Retryable(t.Context(), nil, nil, accessDeniedErr)

		assert.False(t, shouldRetry, "fastFailOnAccessDenied should short-circuit before retryOnScanNotFound")
		require.EqualError(t, err, "AccessDeniedException")
	})
}

func TestFastFailOnAccessDenied(t *testing.T) {
	t.Run("Returns false for AccessDeniedException", func(t *testing.T) {
		assertCalled, retry := setupRetryTest(false, nil, fastFailOnAccessDenied)

		accessDeniedErr := errors.New("AccessDeniedException")

		shouldRetry, err := retry(t.Context(), nil, nil, accessDeniedErr)

		assert.False(t, shouldRetry, "Should not retry on AccessDeniedException")
		require.EqualError(t, err, "AccessDeniedException", "Should return the AccessDeniedException error")
		assertCalled(t, false)
	})

	t.Run("Delegates to wrapped function for other API errors", func(t *testing.T) {
		assertWrapped, retry := setupRetryTest(true, errors.New("wrapped error"), fastFailOnAccessDenied)

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
		assertWrapped, retry := setupRetryTest(false, nil, fastFailOnAccessDenied)

		nonAPIErr := errors.New("non-API error")

		shouldRetry, err := retry(t.Context(), nil, nil, nonAPIErr)

		assert.False(t, shouldRetry, "Should return wrapped function's retry decision")
		require.NoError(t, err, "Should return wrapped function's error")
		assertWrapped(t, true)
	})
}
