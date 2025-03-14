package registry

import (
	"context"
	"errors"
	"fmt"
	"regexp"
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

func (i ImageReference) DisplayName() string {
	return fmt.Sprintf("%s%s%s", i.Name, i.tagRef(), i.digestRef())
}

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

type RegistryScan struct {
	Client *ecr.Client
}

func NewRegistryScan(config aws.Config) (*RegistryScan, error) {
	client := ecr.NewFromConfig(config)

	return &RegistryScan{
		Client: client,
	}, nil
}

func (r *RegistryScan) GetLabelDigest(ctx context.Context, imageInfo ImageReference) (ImageReference, error) {
	out, err := r.Client.DescribeImages(ctx, &ecr.DescribeImagesInput{
		RegistryId:     &imageInfo.RegistryID,
		RepositoryName: &imageInfo.Name,
		ImageIds: []types.ImageIdentifier{
			{
				ImageTag: &imageInfo.Tag,
			},
		},
	})

	if err != nil {
		return ImageReference{}, err
	}
	if len(out.ImageDetails) == 0 {
		return ImageReference{}, fmt.Errorf("no image found for image %s", imageInfo)
	}

	imageDetail := out.ImageDetails[0]

	// copy input and update tag from label to digest
	digestInfo := imageInfo.WithDigest(aws.ToString(imageDetail.ImageDigest))

	return digestInfo, nil
}

func (r *RegistryScan) WaitForScanFindings(ctx context.Context, digestInfo ImageReference) error {
	waiter := ecr.NewImageScanCompleteWaiter(r.Client, optionsScanFindingsRetryPolicy)

	// wait between attempts for between 3 and 15 secs (exponential backoff)
	// wait for a maximum of 3 minutes
	minAttemptDelay := 3 * time.Second
	maxAttemptDelay := 15 * time.Second
	maxTotalDelay := 3 * time.Minute

	err := waiter.Wait(ctx, &ecr.DescribeImageScanFindingsInput{
		RegistryId:     &digestInfo.RegistryID,
		RepositoryName: &digestInfo.Name,
		ImageId: &types.ImageIdentifier{
			ImageDigest: &digestInfo.Digest,
		},
		MaxResults: aws.Int32(1), // reduce the size of the return payload when waiting for the completion state
	}, maxTotalDelay, func(opts *ecr.ImageScanCompleteWaiterOptions) {
		opts.LogWaitAttempts = true
		opts.MinDelay = minAttemptDelay
		opts.MaxDelay = maxAttemptDelay
	})

	// It is not good style to compare the error string, but this is the only way
	// to capture that the scan failed, but everything else is hunky dory. We
	// return nil here so that the caller will gather the scan results, and
	// communicate to the user the reason this image has no results. "FAILURE" is
	// returned when the image is unsupported, for example, and we want to
	// communicate this properly to the user.
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

type RetryPolicyFunc = func(context.Context, *ecr.DescribeImageScanFindingsInput, *ecr.DescribeImageScanFindingsOutput, error) (bool, error)

func optionsScanFindingsRetryPolicy(opts *ecr.ImageScanCompleteWaiterOptions) {
	defaultRetryable := opts.Retryable
	opts.Retryable = scanStateRetryableOnNotFound(defaultRetryable)
}

func scanStateRetryableOnNotFound(wrapped RetryPolicyFunc) RetryPolicyFunc {
	return func(ctx context.Context, input *ecr.DescribeImageScanFindingsInput, output *ecr.DescribeImageScanFindingsOutput, err error) (bool, error) {
		var aerr smithy.APIError
		if err != nil && errors.As(err, &aerr) {
			fmt.Printf("Smithy error?\n%+v\n%+v\n", aerr.ErrorCode(), aerr.ErrorFault())
			if aerr.ErrorCode() == "ScanNotFoundException" {
				fmt.Println("retrying")
				return true, nil
			}
		}

		return wrapped(ctx, input, output, err)
	}
}
