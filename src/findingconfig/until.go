package findingconfig

import (
	"errors"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

const untilFormat = "2006-01-02"

type UntilTime time.Time //nolint:recvcheck

func (u *UntilTime) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return errors.New("unsupported type for Until value")
	}

	t, err := ParseUntil(value.Value)
	if err != nil {
		return err
	}

	*u = t

	return nil
}

func (u UntilTime) IsZero() bool {
	return time.Time(u).IsZero()
}

func (u UntilTime) String() string {
	if u.IsZero() {
		return "never"
	}

	return time.Time(u).Format(untilFormat)
}

func ParseUntil(dt string) (UntilTime, error) {
	tm, err := time.Parse(untilFormat, dt)
	if err != nil {
		return UntilTime{}, fmt.Errorf("supplied until value '%s' did not match the expected YYYY-MM-dd format: %w", dt, err)
	}

	return UntilTime(tm), nil
}

func MustParseUntil(dt string) UntilTime {
	u, err := ParseUntil(dt)
	if err != nil {
		panic(err)
	}

	return u
}
