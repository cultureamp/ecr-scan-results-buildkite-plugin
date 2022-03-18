package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryInfoFromUrlSucceeds(t *testing.T) {
	cases := []struct {
		test     string
		url      string
		expected RegistryInfo
	}{
		{
			test: "Url with label",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo:latest",
			expected: RegistryInfo{
				RegistryID: "123456789012",
				Region:     "us-west-2",
				Name:       "test-repo",
				Tag:        "latest",
			},
		},
		{
			test: "Url without label",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo",
			expected: RegistryInfo{
				RegistryID: "123456789012",
				Region:     "us-west-2",
				Name:       "test-repo",
				Tag:        "",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.test, func(t *testing.T) {
			info, err := RegistryInfoFromUrl(c.url)
			require.NoError(t, err)
			assert.Equal(t, c.expected, info)
		})
	}
}

func TestRegistryInfoFromUrlFails(t *testing.T) {
	url := "123456789012.dkr.ecr.us-west-2.amazonaws.com"

	info, err := RegistryInfoFromUrl(url)
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid registry URL")

	assert.Equal(t, RegistryInfo{}, info)
}
