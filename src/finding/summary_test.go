package finding_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cultureamp/ecrscanresults/finding"
	"github.com/cultureamp/ecrscanresults/findingconfig"
	"github.com/hexops/autogold/v2"
)

func TestSummarize(t *testing.T) {
	cases := []struct {
		name     string
		ignores  []findingconfig.Ignore
		data     types.ImageScanFindings
		expected autogold.Value
	}{
		{
			name: "no vulnerabilities",
			data: types.ImageScanFindings{},
			expected: autogold.Expect(finding.Summary{
				Counts: map[types.FindingSeverity]finding.SeverityCount{
					types.FindingSeverity("CRITICAL"): {},
					types.FindingSeverity("HIGH"):     {},
				},
				Details: []finding.Detail{},
				Ignored: []finding.Detail{},
			}),
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
			expected: autogold.Expect(finding.Summary{
				Counts: map[types.FindingSeverity]finding.SeverityCount{
					types.FindingSeverity("CRITICAL"): {Included: 1},
					types.FindingSeverity("HIGH"):     {Included: 2},
				},
				Details: []finding.Detail{
					{
						Name:     "CVE-2019-5188",
						URI:      "https://www.cve.org/CVERecord?id=CVE-2019-5188",
						Severity: types.FindingSeverity("HIGH"),
					},
					{
						Name:     "INVALID-CVE",
						URI:      "https://github.com/advisories?query=INVALID-CVE",
						Severity: types.FindingSeverity("CRITICAL"),
					},
					{
						Name:     "CVE-2019-5189",
						URI:      "https://notamitre.org.site/search?name=CVE-2019-5189",
						Severity: types.FindingSeverity("HIGH"),
					},
				},
				Ignored: []finding.Detail{},
			}),
		},
		{
			name: "findings with CVSS2 scores",
			data: types.ImageScanFindings{
				Findings: []types.ImageScanFinding{
					fscore("CVE-2019-5188", "HIGH", "1.2", "AV:L/AC:L/Au:N/C:P/I:P/A:P"),
					fscore("INVALID-CVE", "CRITICAL", "", ""),
					fscore("CVE-2019-5189", "HIGH", "", ""),
				},
			},
			expected: autogold.Expect(finding.Summary{
				Counts: map[types.FindingSeverity]finding.SeverityCount{
					types.FindingSeverity("CRITICAL"): {Included: 1},
					types.FindingSeverity("HIGH"):     {Included: 2},
				},
				Details: []finding.Detail{
					{
						Name:     "CVE-2019-5188",
						Severity: types.FindingSeverity("HIGH"),
						CVSS2: finding.CVSSScore{
							Score:     "1.2",
							Vector:    "AV:L/AC:L/Au:N/C:P/I:P/A:P",
							VectorURL: "https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=%28AV%3AL%2FAC%3AL%2FAu%3AN%2FC%3AP%2FI%3AP%2FA%3AP%29",
						},
					},
					{
						Name:     "INVALID-CVE",
						Severity: types.FindingSeverity("CRITICAL"),
					},
					{
						Name:     "CVE-2019-5189",
						Severity: types.FindingSeverity("HIGH"),
					},
				},
				Ignored: []finding.Detail{},
			}),
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
			expected: autogold.Expect(finding.Summary{
				Counts: map[types.FindingSeverity]finding.SeverityCount{
					types.FindingSeverity("CRITICAL"): {Included: 1},
					types.FindingSeverity("HIGH"):     {Included: 2},
				},
				Details: []finding.Detail{
					{
						Name:     "CVE-2019-5188",
						Severity: types.FindingSeverity("HIGH"),
					},
					{
						Name:     "CVE-2019-5200",
						Severity: types.FindingSeverity("CRITICAL"),
					},
					{
						Name:     "CVE-2019-5189",
						Severity: types.FindingSeverity("HIGH"),
					},
				},
				Ignored: []finding.Detail{},
			}),
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
			expected: autogold.Expect(finding.Summary{
				Counts: map[types.FindingSeverity]finding.SeverityCount{
					types.FindingSeverity("CRITICAL"): {Included: 1},
					types.FindingSeverity("HIGH"): {
						Included: 1,
						Ignored:  1,
					},
				},
				Details: []finding.Detail{
					{
						Name:     "CVE-2019-5188",
						Severity: types.FindingSeverity("HIGH"),
					},
					{
						Name:     "CVE-2019-5200",
						Severity: types.FindingSeverity("CRITICAL"),
					},
				},
				Ignored: []finding.Detail{{
					Name:     "CVE-2019-5189",
					Severity: types.FindingSeverity("HIGH"),
					Ignore: &findingconfig.Ignore{
						ID: "CVE-2019-5189",
					},
				}},
			}),
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			summary := finding.Summarize(&c.data, c.ignores)

			c.expected.Equal(t, summary)
		})
	}
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

func i(id string) findingconfig.Ignore {
	return findingconfig.Ignore{ID: id}
}
