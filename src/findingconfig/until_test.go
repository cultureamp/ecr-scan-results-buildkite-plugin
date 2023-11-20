package findingconfig_test

import (
	"testing"
	"time"

	"github.com/cultureamp/ecrscanresults/findingconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestParseUntil(t *testing.T) {
	type timer struct {
		Until findingconfig.UntilTime
	}

	in := `
until: 2015-02-15
`

	var out timer
	err := yaml.Unmarshal([]byte(in), &out)
	require.NoError(t, err)

	expected, _ := time.Parse("2006-01-02", "2015-02-15")

	assert.Equal(t, timer{findingconfig.UntilTime(expected)}, out)

}
