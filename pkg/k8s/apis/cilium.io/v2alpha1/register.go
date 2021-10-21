// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
)

const (
	// CustomResourceDefinitionGroup is the name of the third party resource group
	CustomResourceDefinitionGroup = k8sconst.CustomResourceDefinitionGroup

	// CustomResourceDefinitionVersion is the current version of the resource
	CustomResourceDefinitionVersion = "v2alpha1"

	// CustomResourceDefinitionSchemaVersion is semver-conformant version of CRD schema
	// Used to determine if CRD needs to be updated in cluster
	//
	// Maintainers: Run ./Documentation/check-crd-compat-table.sh for each release
	// Developers: Bump patch for each change in the CRD schema.
	CustomResourceDefinitionSchemaVersion = "1.25.5"

	// CustomResourceDefinitionSchemaVersionKey is key to label which holds the CRD schema version
	CustomResourceDefinitionSchemaVersionKey = "io.cilium.k8s.crd.schema.version"

	// Cilium Egress NAT Policy (CENP)

	// CENPSingularName is the singular name of Cilium Egress NAT Policy
	CENPSingularName = "ciliumegressnatpolicy"

	// CENPPluralName is the plural name of Cilium Egress NAT Policy
	CENPPluralName = "ciliumegressnatpolicies"

	// CENPKindDefinition is the kind name of Cilium Egress NAT Policy
	CENPKindDefinition = "CiliumEgressNATPolicy"

	// CENPName is the full name of Cilium Egress NAT Policy
	CENPName = CENPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium Endpoint Slice (CES)

	// CESSingularName is the singular name of Cilium Endpoint Slice
	CESSingularName = "ciliumendpointslice"

	// CESPluralName is the plural name of Cilium Endpoint Slice
	CESPluralName = "ciliumendpointslices"

	// CESKindDefinition is the kind name of Cilium Endpoint Slice
	CESKindDefinition = "CiliumEndpointSlice"

	// CESName is the full name of Cilium Endpoint Slice
	CESName = CESPluralName + "." + CustomResourceDefinitionGroup

	// Cilium SRv6 Egress Policy (CSREP)

	// CSREPSingularName is the singular name of Cilium SRv6 Egress Policy
	CSREPSingularName = "ciliumsrv6egresspolicy"

	// CSREPPluralName is the plural name of Cilium SRv6 Egress Policy
	CSREPPluralName = "ciliumsrv6egresspolicies"

	// CSREPKindDefinition is the kind name of Cilium SRv6 Egress Policy
	CSREPKindDefinition = "CiliumSRv6EgressPolicy"

	// CSREPName is the full name of Cilium SRv6 Egress Policy
	CSREPName = CSREPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium SRv6 VRF (CSRVRF)

	// CSRVRFSingularName is the singular name of Cilium SRv6 VRF
	CSRVRFSingularName = "ciliumsrv6vrf"

	// CSRVRFPluralName is the plural name of Cilium SRv6 VRF
	CSRVRFPluralName = "ciliumsrv6vrfs"

	// CSRVRFKindDefinition is the kind name of Cilium SRv6 VRF
	CSRVRFKindDefinition = "CiliumSRv6VRF"

	// CSRVRFName is the full name of Cilium SRv6 VRF
	CSRVRFName = CSRVRFPluralName + "." + CustomResourceDefinitionGroup

	// Cilium BGP Peering Policy (BGPP)

	// BGPPSingularName is the singular name of Cilium BGP Peering Policy
	BGPPSingularName = "ciliumbgppeeringpolicy"

	// BGPPPluralName is the plural name of Cilium BGP Peering Policy
	BGPPPluralName = "ciliumbgppeeringpolicies"

	// BGPPKindDefinition is the kind name of Cilium BGP Peering Policy
	BGPPKindDefinition = "CiliumBGPPeeringPolicy"

	// BGPPName is the full name of Cilium BGP Peering Policy
	BGPPName = BGPPPluralName + "." + CustomResourceDefinitionGroup

	// Cilium BGP Load Balancer IP Pool (BGPPool)

	// BGPPoolSingularName is the singular name of Cilium BGP Load Balancer IP Pool
	BGPPoolSingularName = "ciliumbgploadbalancerippool"

	// BGPPoolPluralName is the plural name of Cilium BGP Load Balancer IP Pool
	BGPPoolPluralName = "ciliumbgploadbalancerippools"

	// BGPPoolKindDefinition is the kind name of Cilium BGP Peering Policy
	BGPPoolKindDefinition = "CiliumBGPLoadBalancerIPPool"

	// BGPPoolName is the full name of Cilium BGP Load Balancer IP Pool
	BGPPoolName = BGPPoolPluralName + "." + CustomResourceDefinitionGroup
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{
	Group:   CustomResourceDefinitionGroup,
	Version: CustomResourceDefinitionVersion,
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	// SchemeBuilder is needed by DeepCopy generator.
	SchemeBuilder runtime.SchemeBuilder
	// localSchemeBuilder and AddToScheme will stay in k8s.io/kubernetes.
	localSchemeBuilder = &SchemeBuilder

	// AddToScheme adds all types of this clientset into the given scheme.
	// This allows composition of clientsets, like in:
	//
	//   import (
	//     "k8s.io/client-go/kubernetes"
	//     clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	//     aggregatorclientsetscheme "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"
	//   )
	//
	//   kclientset, _ := kubernetes.NewForConfig(c)
	//   aggregatorclientsetscheme.AddToScheme(clientsetscheme.Scheme)
	AddToScheme = localSchemeBuilder.AddToScheme
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes)
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&CiliumEgressNATPolicy{},
		&CiliumEgressNATPolicyList{},
		&CiliumEndpointSlice{},
		&CiliumEndpointSliceList{},
		&CiliumSRv6EgressPolicy{},
		&CiliumSRv6EgressPolicyList{},
		&CiliumSRv6VRF{},
		&CiliumSRv6VRFList{},
		&CiliumBGPPeeringPolicy{},
		&CiliumBGPPeeringPolicyList{},
		&CiliumBGPLoadBalancerIPPool{},
		&CiliumBGPLoadBalancerIPPoolList{},
	)

	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
