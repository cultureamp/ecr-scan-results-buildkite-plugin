package main

import (
	"testing"

	"github.com/cultureamp/ecrscanresults/finding"
	"github.com/stretchr/testify/assert"
)

func TestAnnotationStyleFor(t *testing.T) {
	cases := []struct {
		name                   string
		status                 finding.SummaryStatus
		criticalFindings       int32
		highFindings           int32
		failOnUnmatchedIgnores bool
		unmatchedIgnoresCount  int
		expected               string
	}{
		{
			name:     "ok, no findings",
			status:   finding.StatusOk,
			expected: "info",
		},
		{
			name:             "thresholds exceeded",
			status:           finding.StatusThresholdsExceeded,
			criticalFindings: 1,
			expected:         "error",
		},
		{
			name:         "ok but has critical/high findings under threshold",
			status:       finding.StatusOk,
			highFindings: 1,
			expected:     "warning",
		},
		{
			name:                   "ok, fail-on-unmatched-ignores disabled",
			status:                 finding.StatusOk,
			failOnUnmatchedIgnores: false,
			unmatchedIgnoresCount:  2,
			expected:               "info",
		},
		{
			name:                   "ok, fail-on-unmatched-ignores enabled but nothing unmatched",
			status:                 finding.StatusOk,
			failOnUnmatchedIgnores: true,
			unmatchedIgnoresCount:  0,
			expected:               "info",
		},
		{
			name:                   "build fails solely due to unmatched ignores",
			status:                 finding.StatusOk,
			failOnUnmatchedIgnores: true,
			unmatchedIgnoresCount:  1,
			expected:               "error",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual := annotationStyleFor(c.status, c.criticalFindings, c.highFindings, c.failOnUnmatchedIgnores, c.unmatchedIgnoresCount)
			assert.Equal(t, c.expected, actual)
		})
	}
}
