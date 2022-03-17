package runtimeerrors

import "errors"

// NonFatalError is an error that will not cause the plugin to fail.
type NonFatalError struct {
	Message string
	Wrapped error
}

func (e NonFatalError) Error() string {
	m := e.Message
	if e.Wrapped != nil {
		m += ": " + e.Wrapped.Error()
	}
	return m
}

func (e NonFatalError) Unwrap() error {
	return e.Wrapped
}

func NonFatal(message string, err error) NonFatalError {
	return NonFatalError{
		Message: message,
		Wrapped: err,
	}
}

func IsFatal(err error) bool {
	return !errors.As(err, &NonFatalError{})
}
