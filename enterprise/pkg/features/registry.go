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
	"fmt"

	"github.com/cilium/cilium/pkg/lock"
)

type featureRegistry struct {
	*lock.Mutex
	m map[string]Spec
}

func newRegistry() Registry {
	return &featureRegistry{
		m: map[string]Spec{},
	}
}

// Registry is the interface for feature registration, used by hive to collect
// Ffeature specs.
type Registry interface {
	Register(spec Spec) error
}

// Register registers a feature spec, returns an error if the feature is already
// registered to avoid duplicates.
//
// Currently this is just used for validation, eventually we'll want to use this
// to generate a feature spec document.
func (f *featureRegistry) Register(spec Spec) error {
	f.Lock()
	defer f.Unlock()
	if prev, exits := f.m[spec.ID]; exits {
		return fmt.Errorf("feature %s (%q) already registered", spec.ID, prev.ID)
	}
	f.m[spec.ID] = spec
	return nil
}
