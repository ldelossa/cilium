//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package k8s

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/k8s"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

var (
	// EnterpriseResourcesCell provides a set of shared handles to enterprise-only
	// Kubernetes resources used throughout the Cilium operator.
	//
	// See ResourcesCell for more information.
	EnterpriseResourcesCell = cell.Module(
		"enterprise-operator-resources",
		"Shared Enterprise Kubernetes resources",

		cell.Provide(
			k8s.IsovalentFQDNGroup,
		),
	)
)

type EnterpriseResources struct {
	cell.In

	FQDNGroups resource.Resource[*isovalent_api_v1alpha1.IsovalentFQDNGroup]
}
