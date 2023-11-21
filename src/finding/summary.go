package finding

import (
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cultureamp/ecrscanresults/findingconfig"
)

type SeverityCount struct {
	// Included is the number of findings that count towards the threshold for this severity.
	Included int32

	// Ignored is the number of findings that were ignored for the purposes of the threshold.
	Ignored int32
}

type Summary struct {
	// the counts by threshold, taking ignore configuration into account
	Counts map[types.FindingSeverity]SeverityCount

	// the set of finding IDs that have been ignored by configuration
	Ignored map[string]struct{}
}

func NewSummary() Summary {
	return Summary{
		Counts: map[types.FindingSeverity]SeverityCount{
			"CRITICAL": {},
			"HIGH":     {},
		},
		Ignored: map[string]struct{}{},
	}
}

func Summarize(findings *types.ImageScanFindings, ignoreConfig []findingconfig.Ignore) Summary {

	summary := NewSummary()

	for _, f := range findings.Findings {
		ignored := slices.ContainsFunc(ignoreConfig, func(i findingconfig.Ignore) bool {
			return i.ID == *f.Name
		})

		counts := SeverityCount{}
		if c, exists := summary.Counts[f.Severity]; exists {
			counts = c
		}

		if ignored {
			summary.Ignored[*f.Name] = struct{}{}
			counts.Ignored++
		} else {
			counts.Included++
		}

		summary.Counts[f.Severity] = counts
	}

	return summary
}
