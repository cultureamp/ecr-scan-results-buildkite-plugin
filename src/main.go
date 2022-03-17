package main

import (
	"context"
	"encoding/json"
	"io/fs"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Repository string `envconfig:"BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME" required:"true"`
}

func main() {
	var buildConfig Config
	if err := envconfig.Process("", &buildConfig); err != nil {
		log.Fatal(err.Error())
	}
	log.Printf("Config: %+v\n", buildConfig)

	ctx := context.Background()

	awsConfig, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-west-2"))
	if err != nil {
		log.Fatal(err.Error())
	}

	scan, err := NewRegistryScan(awsConfig)
	if err != nil {
		log.Fatal(err.Error())
	}

	imageId, err := RegistryInfoFromUrl(buildConfig.Repository)
	if err != nil {
		log.Fatal(err.Error())
	}

	imageDigest, err := scan.GetLabelDigest(ctx, imageId)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Printf("%s", imageDigest)

	err = scan.WaitForScanFindings(ctx, imageDigest)
	if err != nil {
		log.Fatal(err.Error())
	}

	findings, err := scan.GetScanFindings(ctx, imageDigest)
	if err != nil {
		log.Fatal(err.Error())
	}

	findingSer, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		log.Fatal(err.Error())
	}

	os.WriteFile("result.json", findingSer, fs.ModePerm)

	log.Printf("%+v", findings)
}
