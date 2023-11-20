package findingconfig

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// detailedIgnore represents the detailed encoding of Ignore, used
// for deserialization. Fields must match Ignore.
type detailedIgnore struct {
	ID     string `yaml:"id"`
	Until  UntilTime
	Reason string
}

// An entry in an ignore file used by the plugin.
type Ignore struct {
	ID     string
	Until  UntilTime
	Reason string
}

// UnmarshalYAML is a custom YAML unmarshaller that supports a simple string
// encoding and full encoding that specifies all fields. The simple encoding is
// the string ID, the complex version allows the full ID, Until and Reason
// triple.
func (f *Ignore) UnmarshalYAML(value *yaml.Node) error {
	var deserialized Ignore
	switch value.Kind {
	case yaml.ScalarNode:
		// simple string value, interpret as ID
		deserialized.ID = value.Value

	case yaml.MappingNode:
		// interpret mapping as the full version with all fields
		var fields detailedIgnore
		err := value.Decode(&fields)
		if err != nil {
			return err
		}

		deserialized = Ignore(fields)

	default:
		return fmt.Errorf("unknown type for ignore entry (%d) at line %d:%d", value.Kind, value.Line, value.Column)
	}

	*f = deserialized

	return nil
}

type Ignores struct {
	Ignores []Ignore
}

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
