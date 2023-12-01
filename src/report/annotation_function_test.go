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

func TestCompareCVSSScore(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected int
	}{
		{
			name:     "equal",
			a:        "10",
			b:        "10.0",
			expected: 0,
		},
		{
			name:     "a is greater",
			a:        "10",
			b:        "9.9",
			expected: 1,
		},
		{
			name:     "b is greater",
			a:        "5",
			b:        "10",
			expected: -1,
		},
		{
			name:     "both nil",
			a:        "",
			b:        "",
			expected: 0,
		},
		{
			name:     "only a nil",
			a:        "",
			b:        "10",
			expected: -1,
		},
		{
			name:     "only b nil",
			a:        "5",
			b:        "",
			expected: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			actual := compareCVSSScore(finding.NewCVSS2Score(test.a, ""), finding.NewCVSS2Score(test.b, ""))
			assert.Equal(t, test.expected, actual)
		})
	}
}
