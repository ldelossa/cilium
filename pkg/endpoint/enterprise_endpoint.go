//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package endpoint

import (
	"github.com/cilium/cilium/pkg/maps/policymap"
)

const (
	// PropertyMeshEndpoint represents Cilium endpoints that are Cilium Mesh
	// endpoints.
	PropertyMeshEndpoint = "isovalent-metadata-mesh-endpoint"

	// PropertyIsovalentMeshEndpointName is the key for the CEP name.
	PropertyIsovalentMeshEndpointName = "isovalent-metadata-mesh-endpoint-name"

	// PropertyIsovalentMeshEndpointNamespace is the key for the CEP namespace.
	PropertyIsovalentMeshEndpointNamespace = "isovalent-metadata-mesh-endpoint-namespace"

	// PropertyIsovalentMeshEndpointUID is the key for the CEP UID.
	PropertyIsovalentMeshEndpointUID = "isovalent-metadata-mesh-endpoint-uid"

	// PropertyIsovalentMeshEndpoint is the key for the CEP UID.
	PropertyIsovalentMeshEndpoint = "isovalent-metadata-mesh-endpoint-object"
)

func (e *Endpoint) GetPolicyMap() (*policymap.PolicyMap, error) {
	var err error

	if e.policyMap != nil {
		return e.policyMap, nil
	}

	e.policyMap, err = policymap.OpenOrCreate(e.policyMapPath())
	return e.policyMap, err
}
