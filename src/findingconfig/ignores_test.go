package findingconfig_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/cultureamp/ecrscanresults/findingconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadIgnores_Succeeds(t *testing.T) {
	in := []byte(`
ignores:
  - id: CVE-2023-1234
    until: 2015-02-15
    reason: We don't talk about CVE-2023-1234
  - CVE-2023-9876
`)
	f, err := os.CreateTemp(t.TempDir(), "ignores*.yaml")
	require.NoError(t, err)
	err = os.WriteFile(f.Name(), in, 0600)
	require.NoError(t, err)

	i, err := findingconfig.LoadIgnores(f.Name())
	require.NoError(t, err)

	assert.Equal(t, []findingconfig.Ignore{
		{ID: "CVE-2023-1234", Until: findingconfig.MustParseUntil("2015-02-15"), Reason: "We don't talk about CVE-2023-1234"},
		{ID: "CVE-2023-9876", Until: findingconfig.UntilTime{}, Reason: ""},
	}, i)
}

func TestLoadIgnores_Fails(t *testing.T) {

	cases := []struct {
		in            string
		expectedError string
	}{
		{
			in: `
ignores:
  - ["nested array"]
`,
			expectedError: "unknown type for ignore entry",
		},
		{
			in: `
ignor:
`,
			expectedError: "field ignor not found in type findingconfig.Ignores",
		},
		{
			in: `
ignores:
  - id: CVE-123
    until: 15-Jan-05
`,
			expectedError: "did not match the expected YYYY-MM-dd format",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("cases[%d]", i), func(t *testing.T) {
			in := []byte(c.in)

			f, err := os.CreateTemp(t.TempDir(), "ignores*.yaml")
			require.NoError(t, err)

			err = os.WriteFile(f.Name(), in, 0600)
			require.NoError(t, err)

			_, err = findingconfig.LoadIgnores(f.Name())
			require.ErrorContains(t, err, c.expectedError)
		})
	}

}
