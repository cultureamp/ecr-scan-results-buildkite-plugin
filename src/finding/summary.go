package finding

import (
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cultureamp/ecrscanresults/findingconfig"
)

type Detail struct {
	// The name associated with the finding, usually a CVE number.
	Name string

	URI string

	// The description of the finding.
	Description string

	// The finding severity.
	Severity types.FindingSeverity

	PackageName    string
	PackageVersion string
	CVSS2Score     string
	CVSS2Vector    string

	Ignore *findingconfig.Ignore
}

type SeverityCount struct {
	// Included is the number of findings that count towards the threshold for this severity.
	Included int32

	// Ignored is the number of findings that were ignored for the purposes of the threshold.
	Ignored int32
}

type Summary struct {
	// the counts by threshold, taking ignore configuration into account
	Counts map[types.FindingSeverity]SeverityCount

	Details []Detail

	// the set of finding IDs that have been ignored by configuration
	Ignored []Detail

	// The time of the last completed image scan.
	ImageScanCompletedAt *time.Time

	// The time when the vulnerability data was last scanned.
	VulnerabilitySourceUpdatedAt *time.Time
}

func (s *Summary) addDetail(d Detail) {
	s.Details = append(s.Details, d)
	s.updateCount(d.Severity, SeverityCount{Included: 1})
}

func (s *Summary) addIgnored(d Detail) {
	s.Ignored = append(s.Ignored, d)
	s.updateCount(d.Severity, SeverityCount{Ignored: 1})
}

func (s *Summary) updateCount(severity types.FindingSeverity, updateBy SeverityCount) {
	counts := s.Counts[severity]

	counts.Ignored += updateBy.Ignored
	counts.Included += updateBy.Included

	s.Counts[severity] = counts
}

func newSummary() Summary {
	return Summary{
		Counts: map[types.FindingSeverity]SeverityCount{
			"CRITICAL": {},
			"HIGH":     {},
		},
		Details: []Detail{},
		Ignored: []Detail{},
	}
}

func Summarize(findings *types.ImageScanFindings, ignoreConfig []findingconfig.Ignore) Summary {
	summary := newSummary()

	summary.ImageScanCompletedAt = findings.ImageScanCompletedAt
	summary.VulnerabilitySourceUpdatedAt = findings.VulnerabilitySourceUpdatedAt

	for _, f := range findings.Findings {
		detail := findingToDetail(f)

		index := slices.IndexFunc(ignoreConfig, func(ignore findingconfig.Ignore) bool {
			return ignore.ID == detail.Name
		})

		if index >= 0 {
			detail.Ignore = &ignoreConfig[index]
			summary.addIgnored(detail)
		} else {
			summary.addDetail(detail)
		}
	}

	return summary
}

func findingToDetail(finding types.ImageScanFinding) Detail {
	return Detail{
		Name:           aws.ToString(finding.Name),
		URI:            aws.ToString(finding.Uri),
		Description:    aws.ToString(finding.Description),
		Severity:       finding.Severity,
		PackageName:    findingAttributeValue(finding, "package_name"),
		PackageVersion: findingAttributeValue(finding, "package_version"),
		CVSS2Score:     findingAttributeValue(finding, "CVSS2_SCORE"),
		CVSS2Vector:    findingAttributeValue(finding, "CVSS2_VECTOR"),
	}
}

func findingAttributeValue(finding types.ImageScanFinding, name string) string {
	for _, a := range finding.Attributes {
		if aws.ToString(a.Key) == name {
			return aws.ToString(a.Value)
		}
	}
	return ""
}
