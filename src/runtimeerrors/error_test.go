package runtimeerrors_test

import (
	"fmt"
	"testing"

	"github.com/cultureamp/ecrscanresults/runtimeerrors"
	_ "github.com/hexops/autogold/v2"
	"github.com/stretchr/testify/assert"
)

func TestIIsFatal(t *testing.T) {
	cases := []struct {
		test   string
		result bool
		err    error
	}{
		{
			test:   "true when nil",
			result: true,
			err:    nil,
		},
		{
			test:   "true on normal error",
			result: true,
			err:    assert.AnError,
		},
		{
			test:   "false on nonfatal error",
			result: false,
			err:    runtimeerrors.NonFatalError{},
		},
		{
			test:   "false on wrapped nonfatal error",
			result: false,
			err:    fmt.Errorf("wrapped %w", runtimeerrors.NonFatal("end of the line", nil)),
		},
		{
			test:   "false on nonfatal error in chain",
			result: false,
			err:    fmt.Errorf("wrapped %w", runtimeerrors.NonFatal("wrapped further", assert.AnError)),
		},
	}

	for _, c := range cases {
		t.Run(c.test, func(t *testing.T) {
			result := runtimeerrors.IsFatal(c.err)
			assert.Equal(t, c.result, result)
		})
	}
}
