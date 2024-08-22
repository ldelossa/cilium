// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package annotation

import ossannotation "github.com/cilium/cilium/pkg/annotation"

const (
	// ServiceHealthProbeInterval annotation determines the probe interval of a service.
	// Allowed values:
	//  - A duration, for example:
	//    "service.cilium.io/health-check-probe-interval": "1s"
	ServiceHealthProbeInterval = ossannotation.ServicePrefix + "/health-check-probe-interval"

	// ServiceHealthBGPAdvertiseThreshold annotation defines threshold in minimal number of healthy backends,
	// when service routes will be advertised by the BGP Control Plane.
	// Allowed values:
	//  - A number, for example:
	//      "service.cilium.io/health-check-bgp-advertise-threshold": "1"
	//  - none (default)
	//      same as "1" - the service routes will be advertised when there is at least 1 healthy backend.
	ServiceHealthBGPAdvertiseThreshold = ossannotation.ServicePrefix + "/health-check-bgp-advertise-threshold"

	// ServiceNoAdvertisement annotation is used to disable advertisement
	// of specific Service. This is useful when the service is selected by
	// for example, BGP Control Plane, but we still want to disable
	// advertisement. This annotation is used by the IsovalentLB internally
	// to prevent "placeholder" services from being advertised. It is not
	// intended to be used by users.
	ServiceNoAdvertisement = ossannotation.ServicePrefix + "/no-advertisement"
)
