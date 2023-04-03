// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: xds/type/matcher/v3/cel.proto

package v3

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
)

// Validate checks the field values on CelMatcher with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *CelMatcher) Validate() error {
	if m == nil {
		return nil
	}

	if m.GetExprMatch() == nil {
		return CelMatcherValidationError{
			field:  "ExprMatch",
			reason: "value is required",
		}
	}

	if v, ok := interface{}(m.GetExprMatch()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return CelMatcherValidationError{
				field:  "ExprMatch",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// CelMatcherValidationError is the validation error returned by
// CelMatcher.Validate if the designated constraints aren't met.
type CelMatcherValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e CelMatcherValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e CelMatcherValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e CelMatcherValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e CelMatcherValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e CelMatcherValidationError) ErrorName() string { return "CelMatcherValidationError" }

// Error satisfies the builtin error interface
func (e CelMatcherValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sCelMatcher.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = CelMatcherValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = CelMatcherValidationError{}
