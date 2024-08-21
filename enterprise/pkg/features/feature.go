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
	"reflect"
	"regexp"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const ciliumFeatureTag = "cilium-feature"

type featureChecker[T any] struct {
	allowMissingFlag bool
	enabledValues    []any
	isEnabledFn      func(T) (bool, error)
}

type gateChecker struct {
	allowedFeatures                              sets.Set[string]
	allowAllAlpha, allowAllBeta, allowAllLimited bool
}

const (
	allowAllAlpha   = "AllAlphaFeatures"
	allowAllBeta    = "AllBetaFeatures"
	allowAllLimited = "AllLimitedFeatures"
	allowAll        = "AllFeatures"
)

var logger = logrus.WithField(logfields.LogSubsys, "cilium-feature-checks")

func newGateChecker(fcfg *FeatureGatesConfig) (*gateChecker, error) {
	gc := &gateChecker{
		allowedFeatures: sets.Set[string](sets.NewString(fcfg.FeatureGates...)),
	}
	for _, feature := range fcfg.FeatureGates {
		if len(feature) == 0 {
			return nil, fmt.Errorf("empty feature name in feature-gates not allowed")
		}
		switch feature {
		case allowAllAlpha:
			logger.Info("allowing all alpha features")
			gc.allowAllAlpha = true
			continue
		case allowAllBeta:
			logger.Info("allowing all beta features")
			gc.allowAllBeta = true
			continue
		case allowAllLimited:
			logger.Info("allowing all limited features")
			gc.allowAllLimited = true
			continue
		case allowAll:
			logger.Info("allowing all features (note: this is not recommended for production use)")
			gc.allowAllAlpha = true
			gc.allowAllBeta = true
			gc.allowAllLimited = true
			continue
		}

		logger.Debug("allowing feature", feature)
		gc.allowedFeatures.Insert(feature)
	}

	return gc, nil
}

func featureCheckError(spec Spec) error {
	return fmt.Errorf("%s feature: %s was enabled which is not allowed by default.  "+
		"To use, %s must be explicitly allowed (i.e. --feature-gates=...,%s,...).  "+
		"Please note that this functionality may not be included in your license agreement and may have limited support.  "+
		"Please contact your account team for more information.",
		spec.Stage, spec.ID, spec.ID, spec.ID,
	)
}

func (c *gateChecker) checkFeatureGates(spec Spec) error {
	if spec.Default {
		return nil
	}
	switch spec.Stage {
	case Alpha:
		if c.allowAllAlpha {
			return nil
		}
	case Beta:
		if c.allowAllBeta {
			return nil
		}
	case Limited:
		if c.allowAllLimited {
			return nil
		}
	}
	if c.allowedFeatures != nil && !c.allowedFeatures.Has(spec.ID) {
		return featureCheckError(spec)
	}
	return nil
}

func (f Spec) String() string {
	return fmt.Sprintf("Feature: id=%s name=%q stage=%s default=%v", f.ID, f.Name, f.Stage, f.Default)
}

var featureIDValidRe = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)

// Validate validates a feature spec, a spec must have an ID of the form [A-Z][A-Za-z0-9]*.
// For ex. DatapathEgressGateway, IPModeDualStack, etc.
// As well, the full name and description must be provided.
func (s Spec) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("feature %s has no ID", s.Name)
	}

	if !featureIDValidRe.MatchString(s.ID) {
		return fmt.Errorf("feature %s has invalid ID %q, must match %q", s.Name, s.ID, featureIDValidRe.String())
	}

	if s.Name == "" {
		return fmt.Errorf("feature %s has no name", s.ID)
	}
	if s.Description == "" {
		return fmt.Errorf("feature %s has no description", s.ID)
	}
	return nil
}

type featureOpt[T any] func(*featureChecker[T])

// WithIsEnabledFn overrides the default behavior of determining if a feature is enabled,
// based on an injected config type.
//
// This can be used with FeatureWithConfigT[T] to do feature checking in cases where the
// feature flag is not a bool type, the struct cannot be easily tagged with the cilium-feature=<featureID>,
// or if the feature is enabled by a composite of several values or other special cases (ex. ip dual stack).
func WithIsEnabledFn[T any](fn func(T) (bool, error)) featureOpt[T] {
	return func(check *featureChecker[T]) {
		check.isEnabledFn = fn
	}
}

// By default, bool true values enable a feature.
func defaultValues() []any {
	return []any{true}
}

// FeatureConfig groups Config[T] and FeatureWithConfigT[T] in a single cell, it is useful when you want to declare
// a Config[T] and a corresponding FeatureWithConfigT[T] in the same place.
//
// It is the equivalent of having a cell.Config[T] and a corresponding cell.FeatureWithConfigT[T]
// cell in the same Hive.
func FeatureConfig[T cell.Flagger](cfg T, spec Spec, opts ...featureOpt[T]) cell.Cell {
	return cell.Group(
		cell.Config[T](cfg),
		FeatureWithConfigT[T](spec, opts...),
	)
}

// FeatureWithConfigT registers a Cilium feature that is mapped to a specific cell.Config[T] flagger type.
// Upon running the Hive, the feature is checked against feature gate configuration which validates whether
// this feature can be allowed using current feature gates config.
//
// The generic type variable must be the same as the tagged Config[T] type variable.
// This will be used to be provided with the Config[T] instance when the hive is run, which is then used
// to perform feature checking.
// As such, FeatureWithConfigT[T] will depend on the T type when running the hive.
//
// By default, the feature checker will look for a bool type field on the ConfigT struct with the
// 'cilium-feature=<feature-id>' tag that matches the feature ID in the provided feature Spec.
// It is assumed that if the field is set to true, then the feature is enabled.
//
// For cases where the feature flag is not a boolean type, or is a composite of several values, etc then
// the WithIsEnabledFn(func(T) (bool, error) {...}) option can be used to provide a custom function to determine
// if the feature is enabled.
// This should primarily be used for the legacy option.DaemonConfig type, or in cases where a feature is not enabled
// by a single bool type field (ex. dual-stack feature is enabled if both IPv4 and IPv6 are enabled, see pkg/features/examples
// on how to instrument this).
//
// When possible, prefer using FeatureConfig. FeatureWithConfigT[T] should be used when you need to declare your feature
// and config separately (i.e. such as if in separate files).
func FeatureWithConfigT[ConfigT any](spec Spec, opts ...featureOpt[ConfigT]) cell.Cell {
	var check featureChecker[ConfigT]
	// Default isEnabledFn checks for a bool type field on the ConfigT struct with the
	// 'cilium-feature=<feature-id>' tag that matches the feature ID in the provided feature Spec.
	check.isEnabledFn = func(cfg ConfigT) (bool, error) {
		structType := reflect.TypeOf(cfg)
		structValue := reflect.ValueOf(cfg)

		// Deref any pointer types.
		for {
			if structValue.Kind() == reflect.Pointer {
				if structValue.IsNil() {
					return false, fmt.Errorf("provide feature type %s config is nil", structType.Name())
				}
				structValue = structValue.Elem()
				structType = structType.Elem()
			} else {
				break
			}
		}

		switch structType.Kind() {
		case reflect.Struct:
		default:
			return false, fmt.Errorf("feature %q must be a struct, got %v", spec.ID, structType.Kind())
		}

		var found, enabled bool
		for i := 0; i < structType.NumField(); i++ {
			field := structType.Field(i)
			featureID := field.Tag.Get(ciliumFeatureTag)
			found = true
			if featureID == "" {
				continue
			}
			found = true

			// enabledValues allow passing a list of values that "enable" the feature.
			// By default, bool type "EnableX" type flags are assumed.
			if check.enabledValues == nil {
				check.enabledValues = defaultValues()
			}
			for _, positiveVal := range check.enabledValues {
				if reflect.DeepEqual(structValue.Field(i).Interface(), positiveVal) {
					enabled = true
					break
				}
			}
		}
		if !found && !check.allowMissingFlag {
			return false, fmt.Errorf("feature %q has no feature flag\n"+
				"(hint: when using Feature[T] the T type must be a Config type with a bool var tagged with '%s=<feature-id>')",
				ciliumFeatureTag, spec.ID)
		}
		return enabled, nil
	}

	for _, opt := range opts {
		opt(&check)
	}

	return cell.Group(
		cell.Invoke(func(cfg ConfigT, gc *gateChecker) error {
			if err := spec.Validate(); err != nil {
				return fmt.Errorf("failed to validate feature spec %v: %w", spec, err)
			}

			enabled, err := check.isEnabledFn(cfg)
			if err != nil {
				return err
			}

			if !enabled {
				return nil
			}

			return gc.checkFeatureGates(spec)
		}),
		// Do passthrough decoration to add this feature to the registry.
		// Can be used later to produce a list of features.
		registryDecorator(spec),
	)
}

// Feature just registers a feature in the registry, without doing feature gate checking.
func Feature(spec Spec) cell.Cell {
	return registryDecorator(spec)
}

func registryDecorator(spec Spec) cell.Cell {
	return cell.Decorate(func(reg Registry) (Registry, error) {
		if err := reg.Register(spec); err != nil {
			return nil, err
		}
		return reg, nil
	})
}
