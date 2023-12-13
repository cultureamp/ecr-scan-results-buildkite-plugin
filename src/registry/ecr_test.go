package registry

import (
	"testing"

	"github.com/hexops/autogold/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryInfoFromURLSucceeds(t *testing.T) {
	cases := []struct {
		test     string
		url      string
		expected autogold.Value
	}{
		{
			test: "Url with label",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo:latest",
			expected: autogold.Expect(RegistryInfo{
				RegistryID: "123456789012", Region: "us-west-2",
				Name: "test-repo",
				Tag:  "latest",
			}),
		},
		{
			test: "Url with digest",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo@sha256:hash",
			expected: autogold.Expect(RegistryInfo{
				RegistryID: "123456789012", Region: "us-west-2",
				Name:   "test-repo",
				Digest: "sha256:hash",
			}),
		},
		{
			test: "Url with tag and digest",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo:tagged@sha256:hash",
			expected: autogold.Expect(RegistryInfo{
				RegistryID: "123456789012", Region: "us-west-2",
				Name: "test-repo",
				Tag:  "tagged@sha256:hash",
			}),
		},
		{
			test: "Url without label",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo",
			expected: autogold.Expect(RegistryInfo{
				RegistryID: "123456789012", Region: "us-west-2",
				Name: "test-repo",
			}),
		},
	}

	for _, c := range cases {
		t.Run(c.test, func(t *testing.T) {
			info, err := RegistryInfoFromURL(c.url)
			require.NoError(t, err)
			c.expected.Equal(t, info)
		})
	}
}

func TestRegistryInfoFromURLFails(t *testing.T) {
	url := "123456789012.dkr.ecr.us-west-2.amazonaws.com"

	info, err := RegistryInfoFromURL(url)
	require.ErrorContains(t, err, "invalid registry URL")

	assert.Equal(t, RegistryInfo{}, info)
}
