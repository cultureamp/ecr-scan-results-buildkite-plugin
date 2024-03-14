package finding

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cultureamp/ecrscanresults/findingconfig"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/shopspring/decimal"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type SummaryStatus int

const (
	StatusOk SummaryStatus = iota
	StatusThresholdsExceeded
	StatusAllPlatformsFailed
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

	// Platforms is the set of OS and architecture combinations that the finding
	// was reported for. This may be nil if this finding is for a single image.
	Platforms []v1.Platform
}

type CVSSScore struct {
	Score     *decimal.Decimal
	Vector    string
	VectorURL string
}

func NewCVSS2Score(score string, vector string) CVSSScore {
	return CVSSScore{
		Score:     convertScore(score),
		Vector:    vector,
		VectorURL: cvss2VectorURL(vector),
	}
}

func NewCVSS3Score(score string, vector string) CVSSScore {
	correctedVector, vectorURL := cvss3VectorURL(vector)

	return CVSSScore{
		Score:     convertScore(score),
		Vector:    correctedVector,
		VectorURL: vectorURL,
	}
}

type SeverityCount struct {
	// Included is the number of findings that count towards the threshold for this severity.
	Included int32

	// Ignored is the number of findings that were ignored for the purposes of the threshold.
	Ignored int32
}

type PlatformScanFailure struct {
	Platform v1.Platform
	Reason   string
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

	// Platforms is the set of OS and architecture combinations that this summary
	// was collated for. Findings for this summary may be for a single image or
	// for multiple images.
	Platforms []v1.Platform

	// The set of platforms (with reasons) for which the scan failed, and the
	// reason given by AWS for the failure.
	FailedPlatforms []PlatformScanFailure
}

func newSummary() Summary {
	return Summary{
		Counts:          map[types.FindingSeverity]SeverityCount{},
		Details:         []Detail{},
		Ignored:         []Detail{},
		Platforms:       []v1.Platform{},
		FailedPlatforms: []PlatformScanFailure{},
	}
}

// Status returns the status of the summary, taking into account the status of
// all of the platforms included in the target image, as well as the supplied
// vulnerability thresholds.
func (s Summary) Status(criticalThreshold int32, highThreshold int32) SummaryStatus {
	if len(s.Platforms) == len(s.FailedPlatforms) {
		return StatusAllPlatformsFailed
	}

	if s.ThresholdsExceeded(criticalThreshold, highThreshold) {
		return StatusThresholdsExceeded
	}

	return StatusOk
}

// IncludedCounts returns the number of findings that count towards the
// threshold for High and Critical severities.
func (s Summary) IncludedCounts() (int32, int32) {
	return s.includedCountFor("CRITICAL"), s.includedCountFor("HIGH")
}

// ThresholdsExceeded returns true if the number of included findings
// exceed the given thresholds for their respective severities.
func (s Summary) ThresholdsExceeded(criticalThreshold int32, highThreshold int32) bool {
	criticalFindings, highFindings := s.IncludedCounts()

	overThreshold :=
		criticalFindings > criticalThreshold ||
			highFindings > highThreshold

	return overThreshold
}

// includedCountFor returns the number of findings that count towards the
// threshold for the given severity, returning 0 if there are no counts for the
// given severity value.
func (s Summary) includedCountFor(severity types.FindingSeverity) int32 {
	if s.Counts == nil {
		return 0
	}

	counts, ok := s.Counts[severity]
	if !ok {
		return 0
	}

	return counts.Included
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

func (s *Summary) updateCountByStatus(severity types.FindingSeverity, ignored bool) {
	count := SeverityCount{}

	if ignored {
		count.Ignored = 1
	} else {
		count.Included = 1
	}

	s.updateCount(severity, count)
}

func MergeSummaries(summaries []Summary) Summary {
	merged := newSummary()

	// merge findings from the other Summary into this one
	for _, other := range summaries {
		merged = mergeSingle(merged, other)
	}

	return merged
}

// Merge another summary into this one. This assumes that the list of findings
// is sorted by ID, and that the other summary is for a different platform. At
// the end, the details are merged, and counts updated. If a finding appears in
// both summaries, the platforms are merged together, keeping track of the
// plaforms for a given finding.
func mergeSingle(merged, other Summary) Summary {
	// merge findings from the other Summary into this one

	merged.Details = mergeDetails(merged, merged.Details, other.Details)
	merged.Ignored = mergeDetails(merged, merged.Ignored, other.Ignored)

	merged.Platforms = append(merged.Platforms, other.Platforms...)
	merged.FailedPlatforms = append(merged.FailedPlatforms, other.FailedPlatforms...)

	merged.ImageScanCompletedAt = other.ImageScanCompletedAt
	merged.VulnerabilitySourceUpdatedAt = other.VulnerabilitySourceUpdatedAt

	return merged
}

func mergeDetails(summary Summary, merged, other []Detail) []Detail {
	for _, d := range other {
		insertIdx, found := slices.BinarySearchFunc(merged, d, findingByID)

		if found {
			// already exists, update the platform set for the current finding
			updated := merged[insertIdx]
			updated.Platforms = append(updated.Platforms, d.Platforms...)
			merged[insertIdx] = updated
		} else {
			// insert unique finding into sorted list and update counts
			merged = slices.Insert(merged, insertIdx, d)
			summary.updateCountByStatus(d.Severity, d.Ignore != nil)
		}
	}

	return merged
}

// Summarize takes a set of findings from ECR and converts them into a summary
// ready for rendering.
func Summarize(results *ecr.DescribeImageScanFindingsOutput, platform v1.Platform, ignoreConfig []findingconfig.Ignore) Summary {
	summary := newSummary()

	summary.Platforms = []v1.Platform{platform}

	if results.ImageScanStatus != nil && results.ImageScanStatus.Status != types.ScanStatusComplete {
		summary.FailedPlatforms = append(summary.FailedPlatforms, PlatformScanFailure{
			Platform: platform,
			Reason:   aws.ToString(results.ImageScanStatus.Description),
		})
	}

	if results.ImageScanFindings == nil {
		return summary
	}

	findings := results.ImageScanFindings
	summary.ImageScanCompletedAt = findings.ImageScanCompletedAt
	summary.VulnerabilitySourceUpdatedAt = findings.VulnerabilitySourceUpdatedAt

	for _, f := range findings.Findings {
		detail := findingToDetail(f)

		// ensure that the detail has the correct platform for this summary (ready
		// for merging with other summaries).
		detail.Platforms = summary.Platforms

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

	return Detail{
		Name:           name,
		URI:            uri,
		Description:    aws.ToString(finding.Description),
		Severity:       finding.Severity,
		PackageName:    findingAttributeValue(finding, "package_name"),
		PackageVersion: findingAttributeValue(finding, "package_version"),
		CVSS2: NewCVSS2Score(
			findingAttributeValue(finding, "CVSS2_SCORE"),
			findingAttributeValue(finding, "CVSS2_VECTOR"),
		),
		CVSS3: NewCVSS3Score(
			findingAttributeValue(finding, "CVSS3_SCORE"),
			findingAttributeValue(finding, "CVSS3_VECTOR"),
		),
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

// deprecatedCVEURL is the format of the now-deprecated cve.mitre.org CVE URLs.
// While findings still refer to this source, it's in the process of being
// retired and displays a warning when visited.
const deprecatedCVEURL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
const updatedCVEURL = "https://www.cve.org/CVERecord?id="

func fixFindingURI(name string, uri string) string {
	correctedURI := uri

	// transition from the old CVE site that is deprecated
	if strings.HasPrefix(correctedURI, deprecatedCVEURL) {
		correctedURI = strings.Replace(correctedURI, deprecatedCVEURL, updatedCVEURL, 1)
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
	if versionedVector == "" {
		return "", ""
	}

	vector := versionedVector
	version := "3.1"

	if matches := cvss3VectorPattern.FindStringSubmatch(versionedVector); matches != nil {
		version = matches[1]
		vector = matches[2]
	}

	vectorURL := "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator" +
		"?vector=" + url.QueryEscape(vector) +
		"&version=" + url.QueryEscape(version)

	return vector, vectorURL
}

func convertScore(s string) *decimal.Decimal {
	if s == "" {
		return nil
	}

	d, err := decimal.NewFromString(s)
	if err != nil || d.LessThanOrEqual(decimal.Decimal{}) {
		return nil
	}

	return &d
}

func findingByID(a Detail, b Detail) int {
	return strings.Compare(a.Name, b.Name)
}
