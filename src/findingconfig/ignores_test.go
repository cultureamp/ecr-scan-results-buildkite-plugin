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
	in := `
ignores:
  - id: CVE-2023-1234
    until: 2015-02-15
    reason: We don't talk about CVE-2023-1234
  - CVE-2023-9876
`

	f := createIgnoreFile(t, in)
	i, err := findingconfig.LoadIgnores(f)
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
			f := createIgnoreFile(t, c.in)

			_, err := findingconfig.LoadIgnores(f)
			require.ErrorContains(t, err, c.expectedError)
		})
	}
}

func TestLoadExistingIgnores(t *testing.T) {
	contents := []string{
		`
ignores:
`,
		"skip",
		`
ignores: ~`,
		`
ignores:
  - first-issue
  - id: second-issue
    reason: second issue earliest definition
`,
		`
ignores:
- id: second-issue
  reason: second issue this reason should override earlier ones
- third-issue
`,
	}

	files := createIgnoreFiles(t, contents)

	actual, err := findingconfig.LoadExistingIgnores(files)
	require.NoError(t, err)

	assert.Equal(t, []findingconfig.Ignore{
		{ID: "first-issue", Until: findingconfig.UntilTime{}, Reason: ""},
		{ID: "second-issue", Until: findingconfig.UntilTime{}, Reason: "second issue this reason should override earlier ones"},
		{ID: "third-issue", Until: findingconfig.UntilTime{}, Reason: ""},
	}, actual)
}

func createIgnoreFiles(t *testing.T, contents []string) []string {
	t.Helper()

	files := make([]string, 0, len(contents))
	for _, c := range contents {
		nm := "./file-does-not-exist.yaml"

		if c != "skip" {
			nm = createIgnoreFile(t, c)
		}

		files = append(files, nm)
	}

	return files
}

func createIgnoreFile(t *testing.T, contents string) string {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "ignores*.yaml")
	require.NoError(t, err)

	err = os.WriteFile(f.Name(), []byte(contents), 0600)
	require.NoError(t, err)

	return f.Name()
}
