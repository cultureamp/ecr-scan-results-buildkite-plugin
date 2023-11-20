package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cultureamp/ecrscanresults/registry"
	"github.com/justincampbell/timeago"
	"golang.org/x/exp/maps"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

//go:embed annotation.gohtml
var annotationTemplateSource string

type AnnotationContext struct {
	Image                     registry.RegistryInfo
	ImageLabel                string
	ScanFindings              types.ImageScanFindings
	CriticalSeverityThreshold int32
	HighSeverityThreshold     int32
}

func (c AnnotationContext) Render() ([]byte, error) {
	t, err := template.
		New("annotation").
		Funcs(template.FuncMap{
			"titleCase": func(s string) string {
				c := cases.Title(language.English)
				return c.String(s)
			},
			"lowerCase":        strings.ToLower,
			"findingAttribute": findingAttributeValue,
			"nbsp": func(input string) any {
				if len(input) > 0 {
					return input
				} else {
					return template.HTML(`&nbsp;`)
				}
			},
			"timeAgo": func(tm *time.Time) string {
				if tm == nil {
					return ""
				}

				return timeago.FromTime(*tm)
			},
			"sortFindings":   sortFindings,
			"sortSeverities": sortSeverities,
			"string": func(input any) (string, error) {
				if strg, ok := input.(fmt.Stringer); ok {
					return strg.String(), nil
				}

				return fmt.Sprintf("%s", input), nil
			},
		}).
		Parse(annotationTemplateSource)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = t.Execute(&buf, c)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func findingAttributeValue(name string, finding types.ImageScanFinding) string {
	for _, a := range finding.Attributes {
		if aws.ToString(a.Key) == name {
			return aws.ToString(a.Value)
		}
	}
	return ""
}

func sortFindings(findings []types.ImageScanFinding) []types.ImageScanFinding {
	// shallow clone, don't affect source array
	sorted := slices.Clone(findings)

	// sort by severity rank, then CVE _descending_
	slices.SortFunc(sorted, func(a, b types.ImageScanFinding) int {
		sevRank := compareSeverities(string(a.Severity), string(b.Severity))
		if sevRank != 0 {
			return sevRank
		}

		// descending order of CVE, in general this means that newer CVEs will be at
		// the top
		return strings.Compare(aws.ToString(b.Name), aws.ToString(a.Name))
	})

	return sorted
}

func sortSeverities(severityCounts map[string]int32) []string {
	// severities are the map key in the incoming data structure
	severities := maps.Keys(severityCounts)

	slices.SortFunc(severities, compareSeverities)

	return severities
}

// sort severity strings by rank, then alphabetically
func compareSeverities(a, b string) int {
	rank := rankSeverity(a) - rankSeverity(b)

	if rank != 0 {
		return rank
	}

	// for unknown severities, sort alphabetically
	return strings.Compare(a, b)
}

func rankSeverity(s string) int {
	switch s {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "INFORMATIONAL":
		return 4
	case "UNDEFINED":
		return 5
	}

	return 100
}
