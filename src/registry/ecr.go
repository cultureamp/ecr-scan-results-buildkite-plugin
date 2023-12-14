package registry

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"

	ocitypes "github.com/google/go-containerregistry/pkg/v1/types"
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

// GetScannableImageDigest returns the digest of the image with the supplied
// tag. If the image media type is a manifest list, the list will be looked up
// using RemoteRepository.GetImageForArchitecture, and the digest of the image
// with the supplied architecture will be returned.
func (r *RegistryScan) GetScannableImageDigest(ctx context.Context, imageInfo ImageReference) (ImageReference, error) {
	ref, mediaType, err := r.GetLabelDigest(ctx, imageInfo)
	if err != nil {
		return ImageReference{}, err
	}

	// standard image, return immediately
	if !ocitypes.MediaType(mediaType).IsIndex() {
		return ref, nil
	}

	// index image, look up the image for the architecture
	repo := NewRemoteRepository()
	scannableRef, _, err := repo.GetImageForArchitecture(ref, "amd64")
	if err != nil {
		return ImageReference{}, err
	}

	return scannableRef, nil
}

func (r *RegistryScan) GetLabelDigest(ctx context.Context, imageInfo ImageReference) (ImageReference, string, error) {
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
		return ImageReference{}, "", err
	}
	if len(out.ImageDetails) == 0 {
		return ImageReference{}, "", fmt.Errorf("no image found for image %s", imageInfo)
	}

	imageDetail := out.ImageDetails[0]

	// copy input and update tag from label to digest
	digestInfo := imageInfo
	digestInfo.Tag = ""
	digestInfo.Digest = aws.ToString(imageDetail.ImageDigest)

	mediaType := aws.ToString(imageDetail.ImageManifestMediaType)

	return digestInfo, mediaType, nil
}

func (r *RegistryScan) WaitForScanFindings(ctx context.Context, digestInfo ImageReference) error {
	waiter := ecr.NewImageScanCompleteWaiter(r.Client)

	// wait between attempts for between 3 and 15 secs (exponential backoff)
	// wait for a maximum of 3 minutes
	minAttemptDelay := 3 * time.Second
	maxAttemptDelay := 15 * time.Second
	maxTotalDelay := 3 * time.Minute

	return waiter.Wait(ctx, &ecr.DescribeImageScanFindingsInput{
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
