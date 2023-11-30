package finding

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cultureamp/ecrscanresults/findingconfig"
)

type Detail struct {
	// The name associated with the finding, usually a CVE number.
	Name        string
	URI         string
	Description string
	Severity    types.FindingSeverity

	PackageName    string
	PackageVersion string
	CVSS2          CVSSScore
	CVSS3          CVSSScore

	Ignore *findingconfig.Ignore
}

type CVSSScore struct {
	Score     string
	Vector    string
	VectorURL string
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
	name := aws.ToString(finding.Name)
	uri := aws.ToString(finding.Uri)

	uri = fixFindingURI(name, uri)

	cvss2Vector := findingAttributeValue(finding, "CVSS2_VECTOR")
	cvss2VectorURL := cvss2VectorURL(cvss2Vector)

	cvss3Vector := findingAttributeValue(finding, "CVSS3_VECTOR")
	cvss3Vector, cvss3VectorURL := cvss3VectorURL(cvss3Vector)

	return Detail{
		Name:           name,
		URI:            uri,
		Description:    aws.ToString(finding.Description),
		Severity:       finding.Severity,
		PackageName:    findingAttributeValue(finding, "package_name"),
		PackageVersion: findingAttributeValue(finding, "package_version"),
		CVSS2: CVSSScore{
			Score:     findingAttributeValue(finding, "CVSS2_SCORE"),
			Vector:    cvss2Vector,
			VectorURL: cvss2VectorURL,
		},
		CVSS3: CVSSScore{
			Score:     findingAttributeValue(finding, "CVSS3_SCORE"),
			Vector:    cvss3Vector,
			VectorURL: cvss3VectorURL,
		}}
}

func findingAttributeValue(finding types.ImageScanFinding, name string) string {
	for _, a := range finding.Attributes {
		if aws.ToString(a.Key) == name {
			return aws.ToString(a.Value)
		}
	}
	return ""
}

const legacyCVEURL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
const updatedCVEURL = "https://www.cve.org/CVERecord?id="

func fixFindingURI(name string, uri string) string {
	correctedURI := uri

	// transition from the old CVE site that is deprecated
	if strings.HasPrefix(correctedURI, legacyCVEURL) {
		correctedURI = strings.Replace(correctedURI, legacyCVEURL, updatedCVEURL, 1)
	}

	// sometimes links are published that are not valid: in this case point to a
	// GH vuln search as a way to provide some value
	if strings.HasPrefix(correctedURI, updatedCVEURL) && !strings.HasPrefix(name, "CVE-") {
		correctedURI = "https://github.com/advisories?query=" + url.QueryEscape(name)
	}

	return correctedURI
}

func cvss2VectorURL(cvss2Vector string) string {
	if cvss2Vector == "" {
		return ""
	}

	return "https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=" +
		url.QueryEscape("("+cvss2Vector+")")
}

// CVSS3 vector have their version at the front: we need to split this out to
// pass to the calculator URL
var cvss3VectorPattern = regexp.MustCompile(`^CVSS:([\d.]+)/(.+)$`)

func cvss3VectorURL(versionedVector string) (string, string) {
	vector := versionedVector
	vectorURL := ""

	if versionedVector != "" {
		version := "3.1"

		if matches := cvss3VectorPattern.FindStringSubmatch(versionedVector); matches != nil {
			version = matches[1]
			vector = matches[2]
		}

		vectorURL = "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator" +
			"?vector=" + url.QueryEscape(vector) +
			"&version=" + url.QueryEscape(version)
	}

	return vector, vectorURL
}
