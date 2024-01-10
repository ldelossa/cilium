//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package daemonplugins

import (
	"errors"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/plugins"
)

type one struct{}

func newOne(*viper.Viper) (plugins.Instance, error) {
	return &one{}, nil
}

type launcher interface {
	launch(string) error
}

type two struct {
	dep launcher // plugin two requires a launcher dependency
}

func newTwo(*viper.Viper) (plugins.Instance, error) {
	return &two{}, nil
}

func (t *two) AcceptDeps(list plugins.Instances) error {
	for _, i := range list {
		if lcher, ok := i.(launcher); ok {
			t.dep = lcher
		}
	}

	if t.dep == nil {
		return errors.New("failed to find launcher dependency")
	}

	return nil
}

type three struct {
}

func newThree(*viper.Viper) (plugins.Instance, error) {
	return &three{}, nil
}

// launch is only implemented by the third plugin.
func (t *three) launch(string) error {
	// launching something here ....
	return nil
}

func TestMissingDeps(t *testing.T) {
	vp := viper.New()
	inits := []plugins.Init{
		newOne,
		newTwo,
		// newthree providing the launcher is missing
	}

	_, err := Initialize(vp, inits)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find launcher dependency")
}

func TestDeps(t *testing.T) {
	vp := viper.New()
	inits := []plugins.Init{
		newOne,
		newTwo,
		newThree,
	}
	l, err := Initialize(vp, inits)
	require.NoError(t, err)

	// find the second plugin and make sure the dep has gone in.
	found := false
	for _, p := range l {
		i, ok := p.(*two)
		if ok {
			found = true
			require.NotNil(t, i.dep, "dep not properly injected")
		}
	}
	require.True(t, found, "at least one instance should be castable to *two")
}
