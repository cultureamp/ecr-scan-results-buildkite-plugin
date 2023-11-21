package report

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/cultureamp/ecrscanresults/finding"
	"github.com/stretchr/testify/assert"
)

func TestSortSeverities(t *testing.T) {
	input := map[types.FindingSeverity]finding.SeverityCount{
		"INFORMATIONAL": {Included: 1},
		"HIGH":          {Included: 1},
		"LOW":           {Included: 1},
		"MADE-UP":       {Included: 1},
		"AA-UNKNOWN":    {Included: 1},
		"UNDEFINED":     {Included: 1},
		"MEDIUM":        {Included: 1},
		"CRITICAL":      {Included: 1},
	}
	expected := []types.FindingSeverity{
		"CRITICAL",
		"HIGH",
		"MEDIUM",
		"LOW",
		"INFORMATIONAL",
		"UNDEFINED",
		"AA-UNKNOWN",
		"MADE-UP",
	}
	actual := sortSeverities(input)

	assert.Equal(t, expected, actual)
}
