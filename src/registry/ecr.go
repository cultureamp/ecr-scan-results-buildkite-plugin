package registry

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

var registryImageExpr = regexp.MustCompile(`^(?P<registryId>[^.]+)\.dkr\.ecr\.(?P<region>[^.]+).amazonaws.com/(?P<repoName>[^:]+)(?::(?P<tag>.+))?$`)

type RegistryInfo struct {
	// RegistryID is the AWS ECR account ID of the source registry.
	RegistryID string
	// Region is the AWS region of the registry.
	Region string
	// Name is the ECR repository name.
	Name string
	// Tag is the image label or an image digest.
	Tag string
}

func (i RegistryInfo) String() string {
	return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:%s", i.RegistryID, i.Region, i.Name, i.Tag)
}

func RegistryInfoFromUrl(url string) (RegistryInfo, error) {
	info := RegistryInfo{}
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

func (r *RegistryScan) GetLabelDigest(ctx context.Context, imageInfo RegistryInfo) (RegistryInfo, error) {
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
		return RegistryInfo{}, err
	}
	if len(out.ImageDetails) == 0 {
		return RegistryInfo{}, fmt.Errorf("no image found for image %s", imageInfo)
	}

	// copy input and update tag from label to digest
	digestInfo := imageInfo
	digestInfo.Tag = *out.ImageDetails[0].ImageDigest

	return digestInfo, nil
}

func (r *RegistryScan) WaitForScanFindings(ctx context.Context, digestInfo RegistryInfo) error {
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
			ImageDigest: &digestInfo.Tag,
		},
	}, maxTotalDelay, func(opts *ecr.ImageScanCompleteWaiterOptions) {
		opts.LogWaitAttempts = true
		opts.MinDelay = minAttemptDelay
		opts.MaxDelay = maxAttemptDelay
	})
}

func (r *RegistryScan) GetScanFindings(ctx context.Context, digestInfo RegistryInfo) (*ecr.DescribeImageScanFindingsOutput, error) {
	pg := ecr.NewDescribeImageScanFindingsPaginator(r.Client, &ecr.DescribeImageScanFindingsInput{
		RegistryId:     &digestInfo.RegistryID,
		RepositoryName: &digestInfo.Name,
		ImageId: &types.ImageIdentifier{
			ImageDigest: &digestInfo.Tag,
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
