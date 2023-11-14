package report_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cultureamp/ecrscanresults/registry"
	"github.com/cultureamp/ecrscanresults/report"
	"github.com/hexops/autogold/v2"
	"github.com/stretchr/testify/require"
)

func TestReports(t *testing.T) {
	cases := []struct {
		name string
		data report.AnnotationContext
	}{
		{
			name: "no vulnerabilities",
			data: report.AnnotationContext{
				Image: registry.RegistryInfo{
					RegistryID: "0123456789",
					Region:     "us-west-2",
					Name:       "test-repo",
					Tag:        "digest-value",
				},
				ImageLabel:                "",
				ScanFindings:              types.ImageScanFindings{},
				CriticalSeverityThreshold: 0,
				HighSeverityThreshold:     0,
			},
		},
		{
			name: "image label",
			data: report.AnnotationContext{
				Image: registry.RegistryInfo{
					RegistryID: "0123456789",
					Region:     "us-west-2",
					Name:       "test-repo",
					Tag:        "digest-value",
				},
				ImageLabel:                "label of image",
				ScanFindings:              types.ImageScanFindings{},
				CriticalSeverityThreshold: 0,
				HighSeverityThreshold:     0,
			},
		},
		{
			name: "findings included",
			data: report.AnnotationContext{
				Image: registry.RegistryInfo{
					RegistryID: "0123456789",
					Region:     "us-west-2",
					Name:       "test-repo",
					Tag:        "digest-value",
				},
				ImageLabel: "label of image",
				ScanFindings: types.ImageScanFindings{
					FindingSeverityCounts: map[string]int32{
						"HIGH":              1,
						"AA-BOGUS-SEVERITY": 1,
						"CRITICAL":          1,
					},
					Findings: []types.ImageScanFinding{
						{
							Name:        aws.String("CVE-2019-5300"),
							Description: aws.String("Another vulnerability."),
							Uri:         aws.String("http://people.ubuntu.com/~ubuntu-security/cve/CVE-2019-5300"),
							Severity:    "AA-BOGUS-SEVERITY",
							Attributes: []types.Attribute{
								{
									Key:   aws.String("package_version"),
									Value: aws.String("5300-version"),
								},
								{
									Key:   aws.String("package_name"),
									Value: aws.String("5300-package"),
								},
								{
									Key:   aws.String("CVSS2_VECTOR"),
									Value: aws.String("AV:L/AC:L/Au:N/C:P/I:P/A:P"),
								},
								{
									Key:   aws.String("CVSS2_SCORE"),
									Value: aws.String("10.0"),
								},
							},
						},
						{
							Name:        aws.String("CVE-2019-5188"),
							Description: aws.String("A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4. A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability."),
							Uri:         aws.String("http://people.ubuntu.com/~ubuntu-security/cve/CVE-2019-5188"),
							Severity:    "HIGH",
							Attributes: []types.Attribute{
								{
									Key:   aws.String("package_version"),
									Value: aws.String("1.44.1-1ubuntu1.1"),
								},
								{
									Key:   aws.String("package_name"),
									Value: aws.String("e2fsprogs"),
								},
								{
									Key:   aws.String("CVSS2_VECTOR"),
									Value: aws.String("AV:L/AC:L/Au:N/C:P/I:P/A:P"),
								},
								{
									Key:   aws.String("CVSS2_SCORE"),
									Value: aws.String("4.6"),
								},
							},
						},
						{
							Name:        aws.String("CVE-2019-5200"),
							Description: aws.String("Another vulnerability."),
							Uri:         aws.String("http://people.ubuntu.com/~ubuntu-security/cve/CVE-2019-5200"),
							Severity:    "CRITICAL",
							Attributes: []types.Attribute{
								{
									Key:   aws.String("package_version"),
									Value: aws.String("5200-version"),
								},
								{
									Key:   aws.String("package_name"),
									Value: aws.String("5200-package"),
								},
								{
									Key:   aws.String("CVSS2_VECTOR"),
									Value: aws.String("AV:L/AC:L/Au:N/C:P/I:P/A:P"),
								},
								{
									Key:   aws.String("CVSS2_SCORE"),
									Value: aws.String("10.0"),
								},
							},
						},
					},
				},
				CriticalSeverityThreshold: 0,
				HighSeverityThreshold:     0,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fmt.Println(c.name, t.Name())
			result, err := c.data.Render()

			require.NoError(t, err)
			autogold.ExpectFile(t, string(result))
		})
	}
}
