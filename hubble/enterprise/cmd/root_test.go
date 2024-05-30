// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Ensure build fails on versions of Go that are not supported by Hubble.
// This build tag should be kept in sync with the version specified in go.mod.
//go:build go1.18

package cmd

import (
	"bytes"
	"context"
	_ "embed"
	"regexp"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/hubble/cmd/observe"
)

//go:embed aggregation_flags.txt
var expectedAggregationFlags string

//go:embed oidc_flags.txt
var expectedOIDCFlags string

func init() {
	// Override the client so that it always returns an IOReaderObserver with no flows.
	observe.GetHubbleClientFunc = func(_ context.Context, _ *viper.Viper) (client observerpb.ObserverClient, cleanup func() error, err error) {
		cleanup = func() error { return nil }
		return observe.NewIOReaderObserver(new(bytes.Buffer)), cleanup, nil
	}
}

func TestTestHubbleObserve(t *testing.T) {
	tests := []struct {
		name               string
		args               []string
		expectErr          error
		expectedSubstrings []string
		expectedRegexps    []*regexp.Regexp
	}{
		{
			name: "observe no flags",
			args: []string{"observe"},
		},
		{
			name: "observe formatting flags",
			args: []string{"observe", "-o", "json"},
		},
		{
			name: "observe server flags",
			args: []string{"observe", "--server", "foo.example.org", "--tls", "--tls-allow-insecure"},
		},
		{
			name: "observe filter flags",
			args: []string{"observe", "--from-pod", "foo/test-pod-1234", "--type", "l7"},
		},
		{
			name:               "help",
			args:               []string{"--help"},
			expectedSubstrings: []string{expectedOIDCFlags},
			expectedRegexps: []*regexp.Regexp{
				regexp.MustCompile(`(?m)^ {2}login +Login to an OIDC provider$`),
				regexp.MustCompile(`(?m)^ {2}logout +Logout from an OIDC provider$`),
			},
		},
		{
			name:               "observe help",
			args:               []string{"observe", "--help"},
			expectedSubstrings: []string{expectedAggregationFlags, expectedOIDCFlags},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			cli := New()
			cli.SetOut(&b)
			cli.SetArgs(tt.args)
			err := cli.Execute()
			require.Equal(t, tt.expectErr, err)
			output := b.String()
			for _, substr := range tt.expectedSubstrings {
				assert.Contains(t, output, substr)
			}
			for _, re := range tt.expectedRegexps {
				assert.Regexp(t, re, output)
			}
		})
	}
}
