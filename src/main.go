package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/cultureamp/ecrscanresults/buildkite"
	"github.com/cultureamp/ecrscanresults/finding"
	"github.com/cultureamp/ecrscanresults/findingconfig"
	"github.com/cultureamp/ecrscanresults/registry"
	"github.com/cultureamp/ecrscanresults/report"
	"github.com/cultureamp/ecrscanresults/runtimeerrors"
	"github.com/kelseyhightower/envconfig"
)

const pluginEnvironmentPrefix = "BUILDKITE_PLUGIN_ECR_SCAN_RESULTS"

type Config struct {
	Repository                string `envconfig:"IMAGE_NAME" split_words:"true" required:"true"`
	ImageLabel                string `envconfig:"IMAGE_LABEL" split_words:"true"`
	CriticalSeverityThreshold int32  `envconfig:"MAX_CRITICALS" split_words:"true"`
	HighSeverityThreshold     int32  `envconfig:"MAX_HIGHS" split_words:"true"`
}

func main() {
	var pluginConfig Config
	if err := envconfig.Process(pluginEnvironmentPrefix, &pluginConfig); err != nil {
		buildkite.LogFailuref("plugin configuration error: %s\n", err.Error())
		os.Exit(1)
	}
	if pluginConfig.CriticalSeverityThreshold < 0 {
		buildkite.LogFailuref("max-criticals must be greater than or equal to 0")
		os.Exit(1)
	}
	if pluginConfig.HighSeverityThreshold < 0 {
		buildkite.LogFailuref("max-highs must be greater than or equal to 0")
		os.Exit(1)
	}

	ctx := context.Background()
	agent := buildkite.Agent{}

	err := runCommand(ctx, pluginConfig, agent)
	if err != nil {
		buildkite.LogFailuref("plugin execution failed: %s\n", err.Error())

		// For this plugin, we don't want to block the build on most errors:
		// scan access and availability can be quite flakey. For this reason, we
		// wrap most issues in a non-fatal error type.
		if runtimeerrors.IsFatal(err) {
			os.Exit(1)
		} else {
			// Attempt to annotate the build with the issue, but it's OK if the
			// annotation fails. We annotate to notify the user of the issue,
			// otherwise it would be lost in the log.
			annotation := fmt.Sprintf("ECR scan results plugin could not create a result for the image %s", "")
			_ = agent.Annotate(ctx, annotation, "error", hash(pluginConfig.Repository))
		}
	}
}

func runCommand(ctx context.Context, pluginConfig Config, agent buildkite.Agent) error {
	buildkite.Logf("Scan results report requested for %s\n", pluginConfig.Repository)
	buildkite.Logf("Thresholds: criticals %d highs %d\n", pluginConfig.CriticalSeverityThreshold, pluginConfig.HighSeverityThreshold)

	imageID, err := registry.ParseReferenceFromURL(pluginConfig.Repository)
	if err != nil {
		return err
	}

	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(imageID.Region))
	if err != nil {
		return runtimeerrors.NonFatal("could not configure AWS access", err)
	}

	scan, err := registry.NewRegistryScan(awsConfig)
	if err != nil {
		return runtimeerrors.NonFatal("could not set up ECR access", err)
	}

	buildkite.Logf("Getting image digest for %s\n", imageID)
	imageDigest, err := scan.GetLabelDigest(ctx, imageID)
	if err != nil {
		return runtimeerrors.NonFatal("could not find digest for image", err)
	}

	buildkite.Logf("Digest: %s\n", imageDigest)

	buildkite.LogGroupf(":ecr: Creating ECR scan results report for %s\n", imageID)
	err = scan.WaitForScanFindings(ctx, imageDigest)
	if err != nil {
		return runtimeerrors.NonFatal("could not retrieve scan results", err)
	}

	buildkite.Log("report ready, retrieving ...")

	findings, err := scan.GetScanFindings(ctx, imageDigest)
	if err != nil {
		return runtimeerrors.NonFatal("could not retrieve scan results", err)
	}

	buildkite.Logf("retrieved. %d findings in report.\n", len(findings.ImageScanFindings.Findings))

	buildkite.Logf("loading finding ignore files ...\n")

	ignoreConfig, err := findingconfig.LoadExistingIgnores([]string{
		".ecr-scan-results-ignore.yaml",
		".ecr-scan-results-ignore.yml",
		".buildkite/ecr-scan-results-ignore.yaml",
		".buildkite/ecr-scan-results-ignore.yml",
		"buildkite/ecr-scan-results-ignore.yaml",
		"buildkite/ecr-scan-results-ignore.yml",
		"/etc/ecr-scan-results-buildkite-plugin/ignore.yaml",
		"/etc/ecr-scan-results-buildkite-plugin/ignore.yml",
	}, findingconfig.DefaultSystemClock())
	if err != nil {
		return runtimeerrors.NonFatal("could not load finding ignore configuration", err)
	}

	// summarize findings, taking ignore configuration into account
	findingSummary := finding.Summarize(findings.ImageScanFindings, ignoreConfig)

	criticalFindings := findingSummary.Counts["CRITICAL"].Included
	highFindings := findingSummary.Counts["HIGH"].Included
	overThreshold :=
		criticalFindings > pluginConfig.CriticalSeverityThreshold ||
			highFindings > pluginConfig.HighSeverityThreshold

	buildkite.Logf("Severity counts: critical=%d high=%d overThreshold=%v\n", criticalFindings, highFindings, overThreshold)

	buildkite.Log("Creating report annotation...")
	annotationCtx := report.AnnotationContext{
		Image:                     imageID,
		ImageLabel:                pluginConfig.ImageLabel,
		FindingSummary:            findingSummary,
		CriticalSeverityThreshold: pluginConfig.CriticalSeverityThreshold,
		HighSeverityThreshold:     pluginConfig.HighSeverityThreshold,
	}

	annotation, err := annotationCtx.Render()
	if err != nil {
		return runtimeerrors.NonFatal("could not render report", err)
	}
	buildkite.Log("done.")

	annotationStyle := "info"
	if overThreshold {
		annotationStyle = "error"
	} else if criticalFindings > 0 || highFindings > 0 {
		annotationStyle = "warning"
	}

	err = agent.Annotate(ctx, string(annotation), annotationStyle, "scan_results_"+imageDigest.Tag)
	if err != nil {
		return runtimeerrors.NonFatal("could not annotate build", err)
	}

	buildkite.Log("Uploading report as an artifact...")
	filename := fmt.Sprintf("result.%s.html", strings.TrimPrefix(imageDigest.Tag, "sha256:"))
	err = os.WriteFile(filename, annotation, fs.ModePerm)
	if err != nil {
		return runtimeerrors.NonFatal("could not write report artifact", err)
	}

	err = agent.ArtifactUpload(ctx, "result*.html")
	if err != nil {
		return runtimeerrors.NonFatal("could not upload report artifact", err)
	}

	buildkite.Log("done.")

	// exceeding threshold is a fatal error
	if overThreshold {
		return errors.New("vulnerability threshold exceeded")
	}

	return nil
}

func hash(data ...string) string {
	h := sha256.New()
	for _, d := range data {
		h.Write([]byte(d))
	}
	return hex.EncodeToString(h.Sum(nil))
}
