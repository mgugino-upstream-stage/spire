package datastore

import (
	"fmt"
)

const (
	datastoreValidationErrorPrefix = "datastore-validation"
)

type dsError struct {
	err                 error
	msg                 string
	datastoreTypePrefix string
}

func (d *dsError) Error() string {
	if d == nil {
		return ""
	}

	if d.err != nil {
		return fmt.Sprintf("%s: %s", d.datastoreTypePrefix, d.err)
	}

	return fmt.Sprintf("%s: %s", d.datastoreTypePrefix, d.msg)
}

func (d *dsError) Unwrap() error {
	if d == nil {
		return nil
	}

	return d.err
}

type validationError struct {
	err error
	msg string
}

func (v *validationError) Error() string {
	if v == nil {
		return ""
	}

	if v.err != nil {
		return fmt.Sprintf("%s: %s", datastoreValidationErrorPrefix, v.err)
	}

	return fmt.Sprintf("%s: %s", datastoreValidationErrorPrefix, v.msg)
}

func (v *validationError) Unwrap() error {
	if v == nil {
		return nil
	}

	return v.err
}

func newDSError(fmtMsg string, args ...any) error {
	return &dsError{
		msg: fmt.Sprintf(fmtMsg, args...),
	}
}

func newWrappedDSError(err error) error {
	if err == nil {
		return nil
	}

	return &dsError{
		err: err,
	}
}

func NewValidationError(fmtMsg string, args ...any) error {
	return &validationError{
		msg: fmt.Sprintf(fmtMsg, args...),
	}
}

func newWrappedValidationError(err error) error {
	if err == nil {
		return nil
	}

	return &validationError{
		err: err,
	}
}
