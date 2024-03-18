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
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hive"
)

type testConfig struct {
	EnableXXX bool `mapstructure:"enable-xxx" cilium-feature:"Xxx"`
}

func (c testConfig) Flags(flags *pflag.FlagSet) {
	flags.BoolVar(&c.EnableXXX, "enable-xxx", false, "Enable Xxx feature")
}

type testConfig2 struct {
	EnableXXX string `mapstructure:"enable-xxx" cilium-feature:"Xxx"`
}

func (f testConfig2) Flags(flags *pflag.FlagSet) {
	flags.StringVar(&f.EnableXXX, "enable-xxx", "", "Enable xxx feature")
}

func TestFeatureWithFn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	getHive := func(confValue string, fn func(testConfig2) (bool, error)) *hive.Hive {
		return hive.New(
			cell.Provide(func() testConfig2 {
				return testConfig2{EnableXXX: confValue}
			}),
			cell.Provide(func() FeatureGatesConfig {
				return FeatureGatesConfig{
					FeatureGates: []string{},
				}
			}),
			cell.ProvidePrivate(newGateChecker),
			FeatureWithConfigT[testConfig2](Spec{
				ID:          "Xxx",
				Stage:       Alpha,
				Name:        "XXX",
				Description: "XXX",
				Default:     false,
			}, WithIsEnabledFn(fn)),
		)
	}

	err := getHive("meow", func(tc testConfig2) (bool, error) {
		return tc.EnableXXX == "meow", nil
	}).Start(hivetest.Logger(t), ctx)
	assert.Error(t, err)

	err = getHive("meow", func(tc testConfig2) (bool, error) {
		return tc.EnableXXX == "woof", nil
	}).Start(hivetest.Logger(t), ctx)
	assert.NoError(t, err)
}

func TestSpecValidation(t *testing.T) {
	runTestHive := func(spec Spec) (func(), error) {
		h := hive.New(
			cell.Provide(func() (FeatureGatesConfig, testConfig) {
				return FeatureGatesConfig{}, testConfig{}
			}),
			cell.ProvidePrivate(newGateChecker),
			FeatureWithConfigT[testConfig](spec),
		)
		ctx, cancel := context.WithCancel(context.Background())
		return cancel, h.Start(hivetest.Logger(t), ctx)
	}

	cancel, err := runTestHive(Spec{
		ID:          "foo",
		Stage:       Alpha,
		Name:        "-",
		Description: "-",
		Default:     false,
	})
	defer cancel()
	assert.Error(t, err)

	cancel, err = runTestHive(Spec{
		ID:          "Foo X",
		Stage:       Alpha,
		Name:        "foo",
		Description: "-",
		Default:     false,
	})
	defer cancel()
	assert.Error(t, err)

	cancel, err = runTestHive(Spec{
		ID:          "Foo-Z",
		Stage:       Alpha,
		Name:        "foo",
		Description: "-",
		Default:     false,
	})
	defer cancel()
	assert.Error(t, err)

	cancel, err = runTestHive(Spec{
		ID:          "Foo-Z",
		Stage:       Alpha,
		Name:        "",
		Description: "-",
		Default:     false,
	})
	defer cancel()
	assert.Error(t, err)
	cancel, err = runTestHive(Spec{
		ID:          "Foo-Z",
		Stage:       Alpha,
		Name:        "Foo",
		Description: "",
		Default:     false,
	})
	defer cancel()
	assert.Error(t, err)

	cancel, err = runTestHive(Spec{
		ID:          "",
		Stage:       Alpha,
		Name:        "Foo",
		Description: "",
		Default:     false,
	})
	defer cancel()
	assert.Error(t, err)
}

func TestFeature(t *testing.T) {
	runTestHive := func(spec Spec, conf testConfig, allowedGates []string) (func(), error) {
		h := hive.New(
			cell.Provide(func() (FeatureGatesConfig, *testConfig) {
				return FeatureGatesConfig{
					FeatureGates: allowedGates,
				}, &conf
			}),
			cell.ProvidePrivate(newGateChecker),
			FeatureWithConfigT[*testConfig](spec),
		)
		ctx, cancel := context.WithCancel(context.Background())
		return cancel, h.Start(hivetest.Logger(t), ctx)
	}

	cancel, err := runTestHive(Spec{
		ID:          "Xxx",
		Stage:       Alpha,
		Name:        "XXX",
		Description: "XXX",
		Default:     false,
	}, testConfig{EnableXXX: true}, []string{})

	defer cancel()
	assert.Error(t, err)
	cancel, err = runTestHive(Spec{
		ID:          "Xxx",
		Stage:       Beta,
		Name:        "XXX",
		Description: "XXX",
		Default:     false,
	}, testConfig{EnableXXX: true}, []string{})
	assert.Error(t, err)
	defer cancel()

	cancel, err = runTestHive(Spec{
		ID:          "Xxx",
		Stage:       Beta,
		Name:        "XXX",
		Description: "XXX",
		Default:     false,
	}, testConfig{EnableXXX: true}, []string{"Xxx"})
	assert.NoError(t, err)
	defer cancel()

	cancel, err = runTestHive(Spec{
		ID:          "Xxx",
		Stage:       Alpha,
		Name:        "XXX",
		Description: "XXX",
		Default:     false,
	}, testConfig{EnableXXX: true}, []string{allowAllAlpha})
	assert.NoError(t, err)
	defer cancel()

	cancel, err = runTestHive(Spec{
		ID:          "Xxx",
		Stage:       Alpha,
		Name:        "XXX",
		Description: "XXX",
		Default:     true,
	}, testConfig{EnableXXX: true}, []string{})
	assert.NoError(t, err)
	defer cancel()

	cancel, err = runTestHive(Spec{
		ID:          "Xxx",
		Stage:       Beta,
		Name:        "XXX",
		Description: "XXX",
		Default:     true,
	}, testConfig{EnableXXX: true}, []string{allowAllBeta, allowAllLimited})
	assert.NoError(t, err)
	defer cancel()

	cancel, err = runTestHive(Spec{
		ID:          "Xxx",
		Stage:       Limited,
		Name:        "XXX",
		Description: "XXX",
		Default:     true,
	}, testConfig{EnableXXX: true}, []string{allowAllLimited})
	assert.NoError(t, err)
	defer cancel()
}

func Test_gateChecker(t *testing.T) {
	c, err := newGateChecker(FeatureGatesConfig{
		FeatureGates: []string{"A", "B", "C"},
	})
	assert.NoError(t, err)
	assert.False(t, c.allowAllAlpha)
	assert.False(t, c.allowAllBeta)
	assert.Contains(t, c.allowedFeatures, "A")
	assert.Contains(t, c.allowedFeatures, "B")
	assert.Contains(t, c.allowedFeatures, "C")

	c, err = newGateChecker(FeatureGatesConfig{
		FeatureGates: []string{"AllBetaFeatures", "AllAlphaFeatures", "AllLimitedFeatures"},
	})
	assert.NoError(t, err)
	assert.True(t, c.allowAllAlpha)
	assert.True(t, c.allowAllBeta)
	assert.True(t, c.allowAllLimited)
	c, err = newGateChecker(FeatureGatesConfig{
		FeatureGates: []string{},
	})
	assert.NoError(t, err)
	assert.False(t, c.allowAllAlpha)
	assert.False(t, c.allowAllBeta)
	assert.False(t, c.allowAllLimited)
}
