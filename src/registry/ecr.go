package registry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/smithy-go"
)

var registryImageExpr = regexp.MustCompile(`^(?P<registryId>[^.]+)\.dkr\.ecr\.(?P<region>[^.]+).amazonaws.com/(?P<repoName>[^:@]+)(?::(?P<tag>.+))?(?:@(?P<digest>.+))?$`)

type ImageReference struct {
	// RegistryID is the AWS ECR account ID of the source registry.
	RegistryID string
	// Region is the AWS region of the registry.
	Region string
	// Name is the ECR repository name.
	Name string
	// Digest is the image digest segment of the image reference, often prefixed with sha256:.
	Digest string
	// Tag is the image label segment of the image reference
	Tag string
}

// ID returns the known identifier for the image: this is the digest if present, otherwise the tag.
func (i ImageReference) ID() string {
	if i.Digest != "" {
		return i.Digest
	}

	return i.Tag
}

// DisplayName returns the repository name with tag and/or digest, without the
// registry host prefix.
func (i ImageReference) DisplayName() string {
	return fmt.Sprintf("%s%s%s", i.Name, i.tagRef(), i.digestRef())
}

// String returns the full ECR image URL including the registry host, e.g.
// "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:latest".
func (i ImageReference) String() string {
	return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s%s%s", i.RegistryID, i.Region, i.Name, i.tagRef(), i.digestRef())
}

func (i ImageReference) tagRef() string {
	if i.Tag == "" {
		return ""
	}

	return ":" + i.Tag
}

func (i ImageReference) digestRef() string {
	if i.Digest == "" {
		return ""
	}

	return "@" + i.Digest
}

// WithDigest returns a copy of the image reference with the digest set to the
// given value. The tag, if any, is cleared.
func (i ImageReference) WithDigest(digest string) ImageReference {
	ref := i
	ref.Digest = digest
	ref.Tag = ""

	return ref
}

// ParseReferenceFromURL parses an image reference from a supplied ECR image
// identifier.
func ParseReferenceFromURL(url string) (ImageReference, error) {
	info := ImageReference{}
	names := registryImageExpr.SubexpNames()

	match := registryImageExpr.FindStringSubmatch(url)
	if match == nil {
		return info, fmt.Errorf("invalid registry URL: %s", url)
	}

	// build the struct using the named subexpressions from the expression
	for i, value := range match {
		nm := names[i]
		switch nm {
		case "registryId":
			info.RegistryID = value
		case "region":
			info.Region = value
		case "repoName":
			info.Name = value
		case "digest":
			info.Digest = value
		case "tag":
			info.Tag = value
		}
	}

	return info, nil
}

// RegistryScan provides operations for initiating and retrieving ECR image
// scan results.
type RegistryScan struct {
	Client *ecr.Client
}

// NewRegistryScan creates a RegistryScan backed by an ECR client for the
// given AWS configuration.
func NewRegistryScan(config aws.Config) (*RegistryScan, error) {
	client := ecr.NewFromConfig(config)

	return &RegistryScan{
		Client: client,
	}, nil
}

// isRetryableError determines if an error is retryable based on its type and message
func isRetryableError(err error) bool {
	// If no error, no need to retry
	if err == nil {
		return false
	}

	// Check for specific API errors
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		// List of error codes that should not be retried
		nonRetryableCodes := map[string]bool{
			"AccessDeniedException":     false,
			"ValidationException":       false,
			"InvalidParameterException": false,
		}

		// Check if error code is explicitly non-retryable
		if retry, exists := nonRetryableCodes[apiErr.ErrorCode()]; exists {
			return retry
		}

		// Explicitly retryable errors
		retryableCodes := map[string]bool{
			"ThrottlingException":         true,
			"ServiceUnavailableException": true,
			"InternalServerError":         true,
			"RequestTimeout":              true,
			"RequestThrottled":            true,
			"TooManyRequestsException":    true,
			"InternalFailure":             true,
			"Throttling":                  true,
			"ImageNotFoundException":      true, // Specifically retry on ImageNotFound
			"ResourceNotFoundException":   true, // General resource not found - retry
		}

		// Check if error code is explicitly retryable
		if retry, exists := retryableCodes[apiErr.ErrorCode()]; exists {
			return retry
		}

		// For other API errors, retry on 500s (server errors), not on 400s (client errors)
		errorFault := apiErr.ErrorFault()

		return errorFault == smithy.FaultServer
	}

	// For network errors or context timeouts, generally we want to retry
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		// Don't retry if the context was explicitly canceled or timed out
		return false
	}

	// For any other error types, assume they might be temporary network issues and retry
	return true
}

// GetLabelDigest resolves a tag-based image reference to the equivalent
// digest-based reference by looking up the image in ECR.
func (r *RegistryScan) GetLabelDigest(ctx context.Context, imageInfo ImageReference) (ImageReference, error) {
	// Create the ECR API input
	input := &ecr.DescribeImagesInput{
		RegistryId:     &imageInfo.RegistryID,
		RepositoryName: &imageInfo.Name,
		ImageIds: []types.ImageIdentifier{
			{
				ImageTag: &imageInfo.Tag,
			},
		},
	}

	// Configure retry parameters
	maxRetries := 5
	baseDelay := 5 * time.Second
	maxDelay := 30 * time.Second

	// Log the start of the operation
	log.Printf("Getting image digest for %s:%s", imageInfo.Name, imageInfo.Tag)

	var (
		out     *ecr.DescribeImagesOutput
		lastErr error
	)

	// Retry loop

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// If this isn't the first attempt, calculate and sleep for the backoff period
		if attempt > 0 {
			// Calculate backoff with exponential delay: baseDelay * 2^(attempt-1)
			// For attempt 1: baseDelay * 2^0 = baseDelay
			// For attempt 2: baseDelay * 2^1 = baseDelay * 2
			// For attempt 3: baseDelay * 2^2 = baseDelay * 4, etc.
			backoffDelay := baseDelay
			for i := 1; i < attempt; i++ {
				backoffDelay *= 2
			}

			// Enforce maximum delay
			if backoffDelay > maxDelay {
				backoffDelay = maxDelay
			}

			// Log retry information
			log.Printf("Retrying DescribeImages... (attempt %d/%d) after %v delay. Previous error: %v",
				attempt, maxRetries, backoffDelay, lastErr)

			// Create a timer for the backoff delay
			timer := time.NewTimer(backoffDelay)

			// Wait for either the timer to expire or the context to be canceled
			select {
			case <-timer.C:
				// Timer expired, continue with retry
			case <-ctx.Done():
				// Context was canceled, clean up the timer and return context error
				timer.Stop()
				return ImageReference{}, ctx.Err()
			}
		}

		// Make the API call
		var err error

		out, err = r.Client.DescribeImages(ctx, input)

		// If successful, break out of the retry loop
		if err == nil {
			if attempt > 0 {
				log.Printf("DescribeImages succeeded after %d attempts", attempt)
			}

			break
		}

		// Store the error for logging in next iteration
		lastErr = err

		// Log the error
		log.Printf("Error describing images: %v", err)

		// Check if this is a retryable error
		if !isRetryableError(err) {
			log.Printf("Non-retryable error encountered: %v", err)
			return ImageReference{}, err
		}

		// Check if we've reached the max retries
		if attempt == maxRetries {
			log.Printf("Maximum retry attempts (%d) reached. Last error: %v", maxRetries, err)
			return ImageReference{}, fmt.Errorf("failed to describe image after %d attempts: %w", maxRetries, err)
		}
	}

	// Handle no image details found
	if out == nil || len(out.ImageDetails) == 0 {
		return ImageReference{}, fmt.Errorf("no image found for image %s", imageInfo)
	}

	// Extract and return the image digest
	imageDetail := out.ImageDetails[0]
	digestInfo := imageInfo.WithDigest(aws.ToString(imageDetail.ImageDigest))

	return digestInfo, nil
}

// WaiterError is a sentinel error type for waiter conditions, enabling
// specific values like ErrWaiterTimeout to be matched with errors.Is.
type WaiterError string

func (w WaiterError) Error() string {
	return string(w)
}

// IsErrWaiterTimeout reports whether err is ErrWaiterTimeout.
func IsErrWaiterTimeout(w error) bool {
	return errors.Is(w, ErrWaiterTimeout)
}

// ErrWaiterTimeout is returned by WaitForScanFindings when the scan does not
// complete within the maximum wait time.
var ErrWaiterTimeout WaiterError = "image scan waiter timed out"

// WaitForScanFindings blocks until the ECR image scan for digestInfo has
// completed, or until the maximum wait time is exceeded.
func (r *RegistryScan) WaitForScanFindings(ctx context.Context, digestInfo ImageReference) error {
	waiter := ecr.NewImageScanCompleteWaiter(
		r.Client,
		withRetryPolicy(fastFailOnAccessDenied, retryOnScanNotFound),
	)

	// Poll every 3–15s with exponential backoff, up to 3 minutes total.
	minAttemptDelay := 3 * time.Second
	maxAttemptDelay := 15 * time.Second
	maxTotalDelay := 3 * time.Minute

	err := waiter.Wait(ctx,
		&ecr.DescribeImageScanFindingsInput{
			RegistryId:     &digestInfo.RegistryID,
			RepositoryName: &digestInfo.Name,
			ImageId: &types.ImageIdentifier{
				ImageDigest: &digestInfo.Digest,
			},
			MaxResults: aws.Int32(1), // reduce the size of the return payload when waiting for the completion state
		},
		maxTotalDelay,
		func(opts *ecr.ImageScanCompleteWaiterOptions) {
			opts.LogWaitAttempts = true
			opts.MinDelay = minAttemptDelay
			opts.MaxDelay = maxAttemptDelay
		},
	)


	if err != nil && err.Error() == "exceeded max wait time for ImageScanComplete waiter" {
		return ErrWaiterTimeout
	}

	// The SDK has no typed error for a FAILURE scan status, so we compare the
	// message string. A failure state means the scan completed but ECR reported
	// FAILURE (e.g. unsupported image type). Return nil so the caller fetches
	// the findings and surfaces the reason to the user.
	if err != nil && err.Error() == "waiter state transitioned to Failure" {
		return nil
	}

	return err
}

func (r *RegistryScan) GetScanFindings(ctx context.Context, digestInfo ImageReference) (*ecr.DescribeImageScanFindingsOutput, error) {
	pg := ecr.NewDescribeImageScanFindingsPaginator(r.Client, &ecr.DescribeImageScanFindingsInput{
		RegistryId:     &digestInfo.RegistryID,
		RepositoryName: &digestInfo.Name,
		ImageId: &types.ImageIdentifier{
			ImageDigest: &digestInfo.Digest,
		},
	})

	var out *ecr.DescribeImageScanFindingsOutput

	for pg.HasMorePages() {
		pg, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		if out == nil {
			out = pg
		} else if out.ImageScanFindings != nil {
			findings := out.ImageScanFindings
			if findings == nil {
				findings = &types.ImageScanFindings{}
				out.ImageScanFindings = findings
			}

			// build the entire set in memory 🤞
			findings.Findings = append(findings.Findings, pg.ImageScanFindings.Findings...)
			findings.EnhancedFindings = append(findings.EnhancedFindings, pg.ImageScanFindings.EnhancedFindings...)
		}
	}

	return out, nil
}

// RetryPolicyFunc is the signature of the retryable function used by the ECR
// image scan complete waiter. It returns (shouldRetry, err) given the current
// poll response or error.
type RetryPolicyFunc = func(context.Context, *ecr.DescribeImageScanFindingsInput, *ecr.DescribeImageScanFindingsOutput, error) (bool, error)

// withRetryPolicy returns a waiter option that layers the given policy wrappers
// onto the waiter's retryable function. Policies are evaluated in the order
// listed: the first policy sees each error first and may short-circuit before
// later policies are reached.
func withRetryPolicy(policies ...func(RetryPolicyFunc) RetryPolicyFunc) func(*ecr.ImageScanCompleteWaiterOptions) {
	return func(opts *ecr.ImageScanCompleteWaiterOptions) {
		chain := opts.Retryable
		for _, policy := range slices.Backward(policies) {
			chain = policy(chain)
		}
		opts.Retryable = chain
	}
}

// fastFailOnAccessDenied stops retrying immediately on AccessDeniedException.
// IAM permission errors will not resolve on their own, so retrying would only
// burn time against the wait timeout.
func fastFailOnAccessDenied(wrapped RetryPolicyFunc) RetryPolicyFunc {
	return func(ctx context.Context, input *ecr.DescribeImageScanFindingsInput, output *ecr.DescribeImageScanFindingsOutput, err error) (bool, error) {
		if err != nil && strings.Contains(err.Error(), "AccessDeniedException") {
			return false, err
		}

		return wrapped(ctx, input, output, err)
	}
}

// retryOnScanNotFound treats ScanNotFoundException as a retryable condition.
// ECR scan registration is asynchronous; the scan record may not exist yet
// when the waiter first polls.
func retryOnScanNotFound(wrapped RetryPolicyFunc) RetryPolicyFunc {
	return func(ctx context.Context, input *ecr.DescribeImageScanFindingsInput, output *ecr.DescribeImageScanFindingsOutput, err error) (bool, error) {
		var aerr smithy.APIError
		if err != nil && errors.As(err, &aerr) {
			if aerr.ErrorCode() == "ScanNotFoundException" {
				return true, nil
			}
		}

		return wrapped(ctx, input, output, err)
	}
}
