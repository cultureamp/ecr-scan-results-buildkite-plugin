package main

import (
	"context"
	"io/fs"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/cultureamp/ecrscanresults/buildkite"
	"github.com/cultureamp/ecrscanresults/registry"
	"github.com/cultureamp/ecrscanresults/report"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Repository string `envconfig:"BUILDKITE_PLUGIN_ECR_SCAN_RESULTS_IMAGE_NAME" required:"true"`
}

func main() {
	var pluginConfig Config
	if err := envconfig.Process("", &pluginConfig); err != nil {
		buildkite.LogFatalf("plugin configuration error: %s\n", err.Error())
	}

	ctx := context.Background()

	if err := runCommand(ctx, pluginConfig); err != nil {
		buildkite.LogFatalf("command failed: %s\n", err.Error())
	}
}

func runCommand(ctx context.Context, pluginConfig Config) error {
	imageId, err := registry.RegistryInfoFromUrl(pluginConfig.Repository)
	if err != nil {
		return err
	}

	awsConfig, err := createAwsConfiguration(imageId.Region)
	if err != nil {
		return err
	}

	scan, err := registry.NewRegistryScan(awsConfig)
	if err != nil {
		return err
	}

	buildkite.Logf("Getting image digest for %s\n", imageId)
	imageDigest, err := scan.GetLabelDigest(ctx, imageId)
	if err != nil {
		return err
	}

	buildkite.LogGroupf(":ecr: Getting ECR scan results for %s\n", imageDigest)
	err = scan.WaitForScanFindings(ctx, imageDigest)
	if err != nil {
		return err
	}

	findings, err := scan.GetScanFindings(ctx, imageDigest)
	if err != nil {
		return err
	}

	buildkite.LogGroup("Creating report annotation")
	annotationCtx := report.AnnotationContext{
		Image:        imageId,
		ScanFindings: *findings.ImageScanFindings,
	}

	buildkite.Logf("%d findings in report\n", len(annotationCtx.ScanFindings.Findings))

	annotation, err := annotationCtx.Render()
	if err != nil {
		return err
	}

	annotationStyle := "info"
	agent := buildkite.BuildkiteAgent{}

	err = agent.Annotate(ctx, annotationStyle, annotationStyle, "scan_results_"+imageDigest.Tag)
	if err != nil {
		return err
	}

	os.WriteFile("result.html", annotation, fs.ModePerm)

	return nil
}

func createAwsConfiguration(region string) (aws.Config, error) {
	awsConfig, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))

	return awsConfig, err
}