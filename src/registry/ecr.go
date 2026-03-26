package registry

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
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

// GetLabelDigest resolves a tag-based image reference to the equivalent
// digest-based reference by looking up the image in ECR.
func (r *RegistryScan) GetLabelDigest(ctx context.Context, imageInfo ImageReference) (ImageReference, error) {
	out, err := r.Client.DescribeImages(ctx, &ecr.DescribeImagesInput{
		RegistryId:     &imageInfo.RegistryID,
		RepositoryName: &imageInfo.Name,
		ImageIds: []types.ImageIdentifier{
			{ImageTag: &imageInfo.Tag},
		},
	}, func(o *ecr.Options) {
		// ImageNotFoundException is retried because a freshly pushed image
		// tag may not be immediately visible in DescribeImages.
		o.Retryer = retry.AddWithErrorCodes(o.Retryer, "ImageNotFoundException")
		o.Retryer = retry.AddWithMaxAttempts(o.Retryer, 6)
		o.Retryer = retry.AddWithMaxBackoffDelay(o.Retryer, 30*time.Second)
	})
	if err != nil {
		return ImageReference{}, err
	}

	if out == nil || len(out.ImageDetails) == 0 {
		return ImageReference{}, fmt.Errorf("no image found for image %s", imageInfo)
	}

	return imageInfo.WithDigest(aws.ToString(out.ImageDetails[0].ImageDigest)), nil
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
const ErrWaiterTimeout WaiterError = "image scan waiter timed out"

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
		if isAPIError(err, "AccessDeniedException") {
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
		if isAPIError(err, "ScanNotFoundException") {
			return true, nil
		}

		return wrapped(ctx, input, output, err)
	}
}

func isAPIError(err error, codes ...string) bool {
	aerr, ok := errors.AsType[smithy.APIError](err)
	if !ok {
		return false
	}

	return slices.Contains(codes, aerr.ErrorCode())
}
