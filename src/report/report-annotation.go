package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cultureamp/ecrscanresults/registry"
	"github.com/justincampbell/timeago"
)

//go:embed report-annotation.gohtml
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
			"titleCase":        strings.Title,
			"lowerCase":        strings.ToLower,
			"findingAttribute": findingAttributeValue,
			"nbsp": func(input string) interface{} {
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
			"string": func(input interface{}) (string, error) {
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
