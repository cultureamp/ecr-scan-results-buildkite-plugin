package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

var registryImageExpr = regexp.MustCompile("^(?P<registryId>[^.]+)\\.dkr\\.ecr\\.(?P<region>[^.]+).amazonaws.com/(?P<repoName>[^:]+)(?::(?P<tag>.+))?$")

type RegistryInfo struct {
	RegistryID string
	Region     string
	Name       string
	Tag        string
}

func (i RegistryInfo) String() string {
	return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:%s", i.RegistryID, i.Region, i.Name, i.Tag)
}

func RegistryInfoFromUrl(arn string) (RegistryInfo, error) {
	info := RegistryInfo{}
	names := registryImageExpr.SubexpNames()
	match := registryImageExpr.FindStringSubmatch(arn)
	if match == nil {
		return info, fmt.Errorf("invalid registry URL: %s", arn)
	}

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
	digestInfo.Tag = out.ImageDetails[0].ImageTags[0]

	return digestInfo, nil
}

func (r *RegistryScan) GetScanFindings(ctx context.Context, digestInfo RegistryInfo) (*ecr.DescribeImageScanFindingsOutput, error) {
	pg := ecr.NewDescribeImageScanFindingsPaginator(r.Client, &ecr.DescribeImageScanFindingsInput{
		RegistryId:     &digestInfo.RegistryID,
		RepositoryName: &digestInfo.Name,
		ImageId: &types.ImageIdentifier{
			ImageTag: &digestInfo.Tag,
		},
	})
	pageNum := 1
	for pg.HasMorePages() {
		out, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		bytes, err := json.Marshal(out)
		if err != nil {
			return nil, err
		}

		err = ioutil.WriteFile(fmt.Sprintf("result.%02d.json", pageNum), bytes, 0644)
		if err != nil {
			return nil, err
		}

		pageNum++
	}

	return nil, nil
}
