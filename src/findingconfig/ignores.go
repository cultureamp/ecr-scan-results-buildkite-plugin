package findingconfig

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// An entry in an ignore file used by the plugin.
type Ignore struct {
	ID     string `yaml:"id"`
	Until  UntilTime
	Reason string
}

type Ignores struct {
	Ignores []Ignore
}

// LoadExistingIgnores uses LoadIgnores to read any of the given set of files
// that exist. Repeated definitions for the same "Name" will overwrite each
// other. The later definition will take precedence.
func LoadExistingIgnores(filenames []string) ([]Ignore, error) {
	ignores := []Ignore{}

	for _, name := range filenames {
		if strings.HasPrefix(name, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("user home directory not available: %w", err)
			}
			name = home + name[1:]
		}

		if _, err := os.Stat(name); err != nil {
			continue
		}

		partial, err := LoadIgnores(name)
		if err != nil {
			return nil, fmt.Errorf("loading ignore file '%s' failed: %w", name, err)
		}

		ignores = append(ignores, partial...)
	}

	// reverse the loaded ignores so that those loaded last take precedence in the
	// following operations.
	slices.Reverse(ignores)

	// sort keeping duplicates in order they were loaded
	slices.SortStableFunc(ignores, compareIgnoreByID)

	// remove duplicates, keeping the first one
	ignores = slices.CompactFunc(ignores, func(a, b Ignore) bool {
		return compareIgnoreByID(a, b) == 0
	})

	return ignores, nil
}

// LoadIgnores parses a YAML ignore file from the given location.
func LoadIgnores(filename string) ([]Ignore, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var i Ignores
	err = unmarshalYAML(content, &i)
	if err != nil {
		return nil, err
	}

	return i.Ignores, nil
}

// unmarshalYAML decodes a YAML encoded byte stream into the supplied pointer
// field, returning an error if decoding fails. Unknown keys in the source YAML
// will cause unmarshalling to fail. We use more strict parsing to help make
// configuration errors more visible to the users of the plugin.
func unmarshalYAML(in []byte, out any) error {
	r := bytes.NewReader(in)

	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	err := dec.Decode(out)

	return err
}

func compareIgnoreByID(a, b Ignore) int {
	return strings.Compare(a.ID, b.ID)
}
