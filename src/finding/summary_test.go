package finding_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cultureamp/ecrscanresults/finding"
	"github.com/cultureamp/ecrscanresults/findingconfig"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/hexops/autogold/v2"
)

var defaultPlatform = v1.Platform{OS: "default"}

func TestSummarize(t *testing.T) {
	cases := []struct {
		name    string
		ignores []findingconfig.Ignore
		data    types.ImageScanFindings
	}{
		{
			name: "no vulnerabilities",
			data: types.ImageScanFindings{},
		},
		{
			name: "findings with links",
			data: types.ImageScanFindings{
				Findings: []types.ImageScanFinding{
					fu("CVE-2019-5188", "HIGH", "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5188"),
					fu("INVALID-CVE", "CRITICAL", "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1234"),
					fu("CVE-2019-5189", "HIGH", "https://notamitre.org.site/search?name=CVE-2019-5189"),
				},
			},
		},
		{
			name: "findings with CVSS2 and CVSS3 scores",
			data: types.ImageScanFindings{
				Findings: []types.ImageScanFinding{
					fscore("CVE-2019-5188", "HIGH", "1.2", "AV:L/AC:L/Au:N/C:P/I:P/A:P"),
					fscore("INVALID-CVE", "CRITICAL", "", ""),
					fscore("CVE-2019-5189", "HIGH", "6", ""),
					fscore3("CVE-2019-5189", "HIGH", "9", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
				},
			},
		},
		{
			name: "findings with no ignores",
			data: types.ImageScanFindings{
				Findings: []types.ImageScanFinding{
					f("CVE-2019-5188", "HIGH"),
					f("CVE-2019-5200", "CRITICAL"),
					f("CVE-2019-5189", "HIGH"),
				},
			},
		},
		{
			name: "ignores affect counts",
			data: types.ImageScanFindings{
				Findings: []types.ImageScanFinding{
					f("CVE-2019-5188", "HIGH"),
					f("CVE-2019-5200", "CRITICAL"),
					f("CVE-2019-5189", "HIGH"),
				},
			},
			ignores: []findingconfig.Ignore{
				i("CVE-2019-5189"), // part of the summary
				i("CVE-2019-6000"), // not part of it
			},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			summary := finding.Summarize(&c.data, defaultPlatform, c.ignores)

			autogold.ExpectFile(t, summary)
		})
	}
}

func TestMergeSummary(t *testing.T) {
	// base := finding.Summary{
	// 	Platforms: p("base"),
	// 	Counts: map[types.FindingSeverity]finding.SeverityCount{
	// 		"HIGH":     {Included: 2},
	// 		"CRITICAL": {Included: 0},
	// 		"LOW":      {Included: 0},
	// 	},
	// 	Details: []finding.Detail{
	// 		{
	// 			Name:      "CVE-c",
	// 			Severity:  "HIGH",
	// 			Platforms: p("base"),
	// 		},
	// 		{
	// 			Name:      "CVE-a",
	// 			Severity:  "HIGH",
	// 			Platforms: p("base"),
	// 		},
	// 	},
	// }
	others := []finding.Summary{
		{
			Platforms: p("base"),
			Counts: map[types.FindingSeverity]finding.SeverityCount{
				"HIGH": {Included: 2},
			},
			Details: []finding.Detail{
				{
					Name:      "CVE-c",
					Severity:  "HIGH",
					Platforms: p("base"),
				},
				{
					Name:      "CVE-a",
					Severity:  "HIGH",
					Platforms: p("base"),
				},
			},
		},
		{
			Platforms: p("other1"),
			Counts: map[types.FindingSeverity]finding.SeverityCount{
				"HIGH": {Included: 3},
			},
			Details: []finding.Detail{
				{
					Name:      "CVE-c",
					Severity:  "HIGH",
					Platforms: p("other1"),
				},
				{
					Name:      "CVE-a",
					Severity:  "HIGH",
					Platforms: p("other1"),
				},
				{
					Name:      "CVE-b",
					Severity:  "HIGH",
					Platforms: p("other1"),
				},
			},
		},
		{
			Platforms: p("other2"),
			Counts: map[types.FindingSeverity]finding.SeverityCount{
				"HIGH": {Included: 1},
			},
			Details: []finding.Detail{
				{
					Name:      "CVE-d",
					Severity:  "HIGH",
					Platforms: p("other2"),
				},
			},
		},
	}

	// base.Merge(others...)
	base := finding.MergeSummaries(others)

	autogold.ExpectFile(t, base)
}

func p(os string) []v1.Platform {
	return []v1.Platform{{OS: os}}
}

func f(name string, severity types.FindingSeverity) types.ImageScanFinding {
	return types.ImageScanFinding{
		Name:     &name,
		Severity: severity,
	}
}

func fu(name string, severity types.FindingSeverity, uri string) types.ImageScanFinding {
	return types.ImageScanFinding{
		Name:     &name,
		Uri:      &uri,
		Severity: severity,
	}
}

func fscore(name string, severity types.FindingSeverity, cvss2 string, vector string) types.ImageScanFinding {
	return types.ImageScanFinding{
		Name:     &name,
		Severity: severity,
		Attributes: []types.Attribute{
			{Key: aws.String("CVSS2_SCORE"), Value: &cvss2},
			{Key: aws.String("CVSS2_VECTOR"), Value: &vector},
		},
	}
}

func fscore3(name string, severity types.FindingSeverity, score string, vector string) types.ImageScanFinding {
	return types.ImageScanFinding{
		Name:     &name,
		Severity: severity,
		Attributes: []types.Attribute{
			{Key: aws.String("CVSS3_SCORE"), Value: &score},
			{Key: aws.String("CVSS3_VECTOR"), Value: &vector},
		},
	}
}

func i(id string) findingconfig.Ignore {
	return findingconfig.Ignore{ID: id}
}
