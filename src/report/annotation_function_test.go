package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortSeverities(t *testing.T) {
	input := map[string]int32{
		"INFORMATIONAL": 1,
		"HIGH":          1,
		"LOW":           1,
		"MADE-UP":       1,
		"AA-UNKNOWN":    1,
		"UNDEFINED":     1,
		"MEDIUM":        1,
		"CRITICAL":      1,
	}
	expected := []string{
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
