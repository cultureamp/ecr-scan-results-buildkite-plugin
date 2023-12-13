package report_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cultureamp/ecrscanresults/finding"
	"github.com/cultureamp/ecrscanresults/findingconfig"
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
					Digest:     "digest-value",
				},
				ImageLabel:                "",
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
					Digest:     "digest-value",
				},
				ImageLabel:                "label of image",
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
					Digest:     "digest-value",
				},
				ImageLabel: "label of image",
				FindingSummary: finding.Summary{
					Counts: map[types.FindingSeverity]finding.SeverityCount{
						"HIGH":              {Included: 1},
						"AA-BOGUS-SEVERITY": {Included: 1},
						"CRITICAL":          {Included: 1},
					},
					Details: []finding.Detail{
						{
							Name:           "CVE-2019-5300",
							Description:    "Another vulnerability.",
							URI:            "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2019-5300",
							Severity:       "AA-BOGUS-SEVERITY",
							PackageName:    "5300-package",
							PackageVersion: "5300-version",
							CVSS2: finding.NewCVSS2Score(
								"10.0",
								"AV:L/AC:L/Au:N/C:P/I:P/A:P",
							),
						},
						{
							Name:           "CVE-2019-5188",
							Description:    "A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4. A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability.",
							URI:            "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2019-5188",
							Severity:       "HIGH",
							PackageName:    "e2fsprogs",
							PackageVersion: "1.44.1-1ubuntu1.1",
							CVSS2: finding.NewCVSS2Score(
								"4.6",
								"AV:L/AC:L/Au:N/C:P/I:P/A:P",
							),
							CVSS3: finding.NewCVSS3Score(
								"9",
								"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
							),
						},
						{
							Name:           "CVE-2019-5200",
							Description:    "Another vulnerability.",
							URI:            "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2019-5200",
							Severity:       "CRITICAL",
							PackageName:    "5200-package",
							PackageVersion: "5200-version",
							CVSS2: finding.NewCVSS2Score(
								"10.0",
								"AV:L/AC:L/Au:N/C:P/I:P/A:P",
							),
						},
					},
				},
				CriticalSeverityThreshold: 0,
				HighSeverityThreshold:     0,
			},
		},
		{
			name: "some findings ignored",
			data: report.AnnotationContext{
				Image: registry.RegistryInfo{
					RegistryID: "0123456789",
					Region:     "us-west-2",
					Name:       "test-repo",
					Digest:     "digest-value",
				},
				ImageLabel: "label of image",
				FindingSummary: finding.Summary{
					Counts: map[types.FindingSeverity]finding.SeverityCount{
						"HIGH":     {Included: 1},
						"CRITICAL": {Included: 1, Ignored: 1},
						"LOW":      {Included: 0, Ignored: 1},
					},
					Details: []finding.Detail{
						{
							Name:           "CVE-2019-5188",
							Description:    "A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4. A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability.",
							URI:            "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2019-5188",
							Severity:       "HIGH",
							PackageName:    "e2fsprogs",
							PackageVersion: "1.44.1-1ubuntu1.1",
							CVSS2: finding.NewCVSS2Score(
								"4.6",
								"AV:L/AC:L/Au:N/C:P/I:P/A:P",
							),
						},
						{
							Name:           "CVE-2019-5200",
							Description:    "Another vulnerability.",
							URI:            "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2019-5200",
							Severity:       "CRITICAL",
							PackageName:    "5200-package",
							PackageVersion: "5200-version",
							CVSS2: finding.NewCVSS2Score(
								"10.0",
								"AV:L/AC:L/Au:N/C:P/I:P/A:P",
							),
						},
					},
					Ignored: []finding.Detail{
						{
							Name:           "CVE-2023-100",
							Description:    "A vulnerability present in some software but isn't that bad.",
							URI:            "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2023-100",
							Severity:       "LOW",
							PackageName:    "100-package",
							PackageVersion: "100-version",
							CVSS2: finding.NewCVSS2Score(
								"4.0",
								"AV:L/AC:L/Au:N/C:P/I:P/A:P",
							),
							Ignore: &findingconfig.Ignore{
								ID: "CVE-2023-100",
							},
						},
						{
							Name:           "CVE-2019-5300",
							Description:    "Another vulnerability.",
							URI:            "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2019-5300",
							Severity:       "CRITICAL",
							PackageName:    "5300-package",
							PackageVersion: "5300-version",
							CVSS2: finding.NewCVSS2Score(
								"10.0",
								"AV:L/AC:L/Au:N/C:P/I:P/A:P",
							),
							CVSS3: finding.NewCVSS3Score(
								"9",
								"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
							),
							Ignore: &findingconfig.Ignore{
								ID:     "CVE-2019-5300",
								Until:  findingconfig.MustParseUntil("2023-12-31"),
								Reason: "Ignored to give the base image a chance to be updated",
							},
						},
					},
				},
				CriticalSeverityThreshold: 0,
				HighSeverityThreshold:     0,
			},
		},
		{
			name: "sorted findings",
			data: report.AnnotationContext{
				Image: registry.RegistryInfo{
					RegistryID: "0123456789",
					Region:     "us-west-2",
					Name:       "test-repo",
					Digest:     "digest-value",
				},
				ImageLabel: "label of image",
				FindingSummary: finding.Summary{
					Counts: map[types.FindingSeverity]finding.SeverityCount{
						"HIGH":     {Included: 1},
						"CRITICAL": {Included: 1, Ignored: 1},
						"LOW":      {Included: 0, Ignored: 1},
					},
					Details: []finding.Detail{
						{
							Name:     "CVE-a",
							Severity: "HIGH",
							CVSS3:    finding.NewCVSS3Score("5.0", ""),
							CVSS2:    finding.NewCVSS2Score("5.0", ""),
						},
						{
							Name:     "CVE-b",
							Severity: "HIGH",
						},
						{
							Name:     "CVE-c",
							Severity: "HIGH",
						},
						{
							Name:     "CVE-d",
							Severity: "HIGH",
							CVSS2:    finding.NewCVSS2Score("6.0", ""),
						},
						{
							Name:     "CVE-f",
							Severity: "HIGH",
							CVSS3:    finding.NewCVSS3Score("6.0", ""),
							CVSS2:    finding.NewCVSS2Score("4.0", ""),
						},
						{
							Name:     "CVE-g",
							Severity: "HIGH",
							CVSS2:    finding.NewCVSS3Score("8.0", ""),
						},
						{
							Name:     "CVE-h",
							Severity: "HIGH",
							CVSS3:    finding.NewCVSS2Score("9.0", ""),
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
