//nolint:goheader
// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package features

import (
	"strings"

	"github.com/blang/semver/v4"
)

type Version semver.Version

// Spec represents a feature specification, which is used to register a feature in the Hive
// and perform feature gate checks.
type Spec struct {
	// ID is the unique identifier of the feature.
	ID string
	// Name is the full name of the feature, it may contain spaces.
	Name string
	// Description is a short description of the feature. This will be used to generate documentation
	// regarding the feature (with respect to the stage of the feature).
	Description string
	// Default is true when the feature is enabled by default, ignoring the stage of the feature.
	Default bool
	// Stage is the readiness stage of the feature, this must be one of Alpha, Beta, or Stable.
	// If Default is false, then stage is used to determine if the feature requires a feature gate
	// to be enabled.
	Stage Readiness
	// Since is an optional field that can be used to specify the version when the feature
	// was introduced.
	Since Version
}

// Readiness represents the maturity stage of a feature.
// This should be one of the Alpha, Beta, or Stable constants.
type Readiness string

func (r Readiness) String() string {
	if r == "" {
		return ""
	}
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

const (
	// Alpha represents an alpha stage feature, this is generally a feature that is
	// either under active development or lacks sufficient testing for production use.
	// Alpha features are not supported for any level of use for Cilium Enterprise.
	Alpha Readiness = "alpha"

	// Beta represents a beta stage feature, this is generally a feature that is
	// feature complete but not production ready.
	// Beta features require more testing and hardening under various conditions before
	// they can be promoted to limited/stable.
	Beta Readiness = "beta"

	// Limited is a feature that is appropriate for production use in a limited set of
	// of environments and configurations.
	Limited Readiness = "limited"

	// Stable is a feature that is appropriate for production use in a variety of supported
	// configurations due to significant hardening from testing and use.
	Stable Readiness = "stable"
)
