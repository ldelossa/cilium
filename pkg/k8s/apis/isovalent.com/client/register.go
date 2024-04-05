// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	_ "embed"
	"fmt"

	"golang.org/x/sync/errgroup"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/k8s/apis/crdhelpers"
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com"
	k8sconstv1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8sconstv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	// subsysK8s is the value for logfields.LogSubsys
	subsysK8s = "k8s"

	// IFGCRDName is the full name of the IsovalentFQDNGroup CRD.
	IFGCRDName = k8sconstv1alpha1.IFGKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IEGPCRDName is the full name of the IsovalentEgressGatewayPolicy CRD.
	IEGPCRDName = k8sconstv1.IEGPKindDefinition + "/" + k8sconstv1.CustomResourceDefinitionVersion

	// SRv6SIDManagerName is the full name of the IsovalentSRv6SIDManager CRD.
	SRv6SIDManagerName = k8sconstv1alpha1.SRv6SIDManagerKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// SRv6LocatorPoolName is the full name of the SRv6LocatorPool CRD.
	SRv6LocatorPoolName = k8sconstv1alpha1.SRv6LocatorPoolKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// SRv6EgressPolicyName is the full name of the IsovalentSRv6EgressPolicy CRD.
	SRv6EgressPolicyName = k8sconstv1alpha1.SRv6EgressPolicyKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// VRFName is the full name of the IsovalentSRv6EgressPolicy CRD.
	VRFName = k8sconstv1alpha1.VRFKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IPNCRDName is the full name of the IsovalentPodNetwork CRD.
	IPNCRDName = k8sconstv1alpha1.IPNKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// MulticastGroupCRDName is the full name of the MulticastGroup CRD.
	MulticastGroupCRDName = k8sconstv1alpha1.MulticastGroupKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// MulticastNodeCRDName is the full name of the MulticastNode CRD.
	MulticastNodeCRDName = k8sconstv1alpha1.MulticastNodeKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion

	// IsovalentMeshEndpointCRDName is the full name of the IsovalentMeshEndpoint CRD.
	IsovalentMeshEndpointCRDName = k8sconstv1alpha1.IsovalentMeshEndpointKindDefinition + "/" + k8sconstv1alpha1.CustomResourceDefinitionVersion
)

// log is the k8s package logger object.
var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)

type crdCreationFn func(clientset apiextensionsclient.Interface) error

// CreateCustomResourceDefinitions creates our CRD objects in the Kubernetes
// cluster.
func CreateCustomResourceDefinitions(clientset apiextensionsclient.Interface) error {
	g, _ := errgroup.WithContext(context.Background())

	resourceToCreateFnMapping := map[string]crdCreationFn{
		synced.CRDResourceName(k8sconstv1alpha1.IFGName):                   createIFGCRD,
		synced.CRDResourceName(k8sconstv1alpha1.SRv6SIDManagerName):        createSRv6SIDManagerCRD,
		synced.CRDResourceName(k8sconstv1alpha1.SRv6LocatorPoolName):       createSRv6LocatorPoolCRD,
		synced.CRDResourceName(k8sconstv1alpha1.SRv6EgressPolicyName):      createSRv6EgressPolicyCRD,
		synced.CRDResourceName(k8sconstv1alpha1.VRFName):                   createVRFCRD,
		synced.CRDResourceName(k8sconstv1.IEGPName):                        createIEGPCRD,
		synced.CRDResourceName(k8sconstv1alpha1.IPNName):                   createIPNCRD,
		synced.CRDResourceName(k8sconstv1alpha1.MulticastGroupName):        createMulticastGroupCRD,
		synced.CRDResourceName(k8sconstv1alpha1.MulticastNodeName):         createMulticastNodeCRD,
		synced.CRDResourceName(k8sconstv1alpha1.IsovalentMeshEndpointName): createIsovalentMeshEndpointCRD,
	}
	for _, r := range synced.AllIsovalentCRDResourceNames() {
		fn, ok := resourceToCreateFnMapping[r]
		if !ok {
			log.Fatalf("Unknown resource %s. Please update pkg/k8s/apis/isovalent.com/client to understand this type.", r)
		}
		g.Go(func() error {
			return fn(clientset)
		})
	}

	return g.Wait()
}

var (
	//go:embed crds/v1alpha1/isovalentfqdngroups.yaml
	crdsv1Alpha1IsovalentFQDNGroups []byte

	//go:embed crds/v1alpha1/isovalentsrv6sidmanagers.yaml
	crdsv1Alpha1IsovalentSRv6SIDManagers []byte

	//go:embed crds/v1alpha1/isovalentsrv6locatorpools.yaml
	crdsv1Alpha1IsovalentSRv6LocatorPools []byte

	//go:embed crds/v1alpha1/isovalentsrv6egresspolicies.yaml
	crdsv1Alpha1IsovalentSRv6EgressPolicies []byte

	//go:embed crds/v1alpha1/isovalentvrfs.yaml
	crdsv1Alpha1IsovalentVRFs []byte

	//go:embed crds/v1/isovalentegressgatewaypolicies.yaml
	crdsv1IsovalentEgressGatewayPolicies []byte

	//go:embed crds/v1alpha1/isovalentpodnetworks.yaml
	crdsv2Alpha1IsovalentPodNetworks []byte

	//go:embed crds/v1alpha1/isovalentmulticastgroups.yaml
	crdsv1Alpha1IsovalentMulticastGroups []byte

	//go:embed crds/v1alpha1/isovalentmulticastnodes.yaml
	crdsv1Alpha1IsovalentMulticastNodes []byte

	//go:embed crds/v1alpha1/isovalentmeshendpoints.yaml
	crdsv2Alpha1Isovalentmeshendpoints []byte
)

// GetPregeneratedCRD returns the pregenerated CRD based on the requested CRD
// name. The pregenerated CRDs are generated by the controller-gen tool and
// serialized into binary form by go-bindata. This function retrieves CRDs from
// the binary form.
func GetPregeneratedCRD(crdName string) apiextensionsv1.CustomResourceDefinition {
	var (
		err      error
		crdBytes []byte
	)

	scopedLog := log.WithField("crdName", crdName)

	switch crdName {
	case IFGCRDName:
		crdBytes = crdsv1Alpha1IsovalentFQDNGroups
	case SRv6SIDManagerName:
		crdBytes = crdsv1Alpha1IsovalentSRv6SIDManagers
	case SRv6LocatorPoolName:
		crdBytes = crdsv1Alpha1IsovalentSRv6LocatorPools
	case SRv6EgressPolicyName:
		crdBytes = crdsv1Alpha1IsovalentSRv6EgressPolicies
	case VRFName:
		crdBytes = crdsv1Alpha1IsovalentVRFs
	case IEGPCRDName:
		crdBytes = crdsv1IsovalentEgressGatewayPolicies
	case IPNCRDName:
		crdBytes = crdsv2Alpha1IsovalentPodNetworks
	case MulticastGroupCRDName:
		crdBytes = crdsv1Alpha1IsovalentMulticastGroups
	case MulticastNodeCRDName:
		crdBytes = crdsv1Alpha1IsovalentMulticastNodes
	case IsovalentMeshEndpointCRDName:
		crdBytes = crdsv2Alpha1Isovalentmeshendpoints
	default:
		scopedLog.Fatal("Pregenerated CRD does not exist")
	}

	ciliumCRD := apiextensionsv1.CustomResourceDefinition{}
	err = yaml.Unmarshal(crdBytes, &ciliumCRD)
	if err != nil {
		scopedLog.WithError(err).Fatal("Error unmarshalling pregenerated CRD")
	}

	return ciliumCRD
}

// createIFGCRD creates and updates the IsovalentFQDNGroup CRD.
func createIFGCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(IFGCRDName)

	return crdhelpers.CreateUpdateCRD(
		clientset,
		constructV1CRD(k8sconstv1alpha1.IFGName, ciliumCRD),
		crdhelpers.NewDefaultPoller(),
		k8sconst.CustomResourceDefinitionSchemaVersionKey,
		versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
	)
}

// createIEGPCRD creates and updates the IsovalentEgressGatewayPolicy CRD.
func createIEGPCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(IEGPCRDName)

	return crdhelpers.CreateUpdateCRD(
		clientset,
		constructV1CRD(k8sconstv1.IEGPName, ciliumCRD),
		crdhelpers.NewDefaultPoller(),
		k8sconst.CustomResourceDefinitionSchemaVersionKey,
		versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
	)
}

// createSRv6SIDManagerCRD creates and updates the IsovalentSRv6SIDManager CRD.
func createSRv6SIDManagerCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(SRv6SIDManagerName)

	return crdhelpers.CreateUpdateCRD(
		clientset,
		constructV1CRD(k8sconstv1alpha1.SRv6SIDManagerName, ciliumCRD),
		crdhelpers.NewDefaultPoller(),
		k8sconst.CustomResourceDefinitionSchemaVersionKey,
		versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
	)
}

// createSRv6LocatorPoolCRD creates and updates the IsovalentSRv6LocatorPool CRD.
func createSRv6LocatorPoolCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(SRv6LocatorPoolName)

	return crdhelpers.CreateUpdateCRD(
		clientset,
		constructV1CRD(k8sconstv1alpha1.SRv6LocatorPoolName, ciliumCRD),
		crdhelpers.NewDefaultPoller(),
		k8sconst.CustomResourceDefinitionSchemaVersionKey,
		versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
	)
}

// createSRv6EgressPolicyCRD creates and updates the IsovalentSRv6EgressPolicy CRD.
func createSRv6EgressPolicyCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(SRv6EgressPolicyName)

	return crdhelpers.CreateUpdateCRD(
		clientset,
		constructV1CRD(k8sconstv1alpha1.SRv6EgressPolicyName, ciliumCRD),
		crdhelpers.NewDefaultPoller(),
		k8sconst.CustomResourceDefinitionSchemaVersionKey,
		versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
	)
}

// createVRFCRD creates and updates the IsovalentVRF CRD.
func createVRFCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(VRFName)

	return crdhelpers.CreateUpdateCRD(
		clientset,
		constructV1CRD(k8sconstv1alpha1.VRFName, ciliumCRD),
		crdhelpers.NewDefaultPoller(),
		k8sconst.CustomResourceDefinitionSchemaVersionKey,
		versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
	)
}

// createIPNCRD creates and updates the IsovalentPodNetwork CRD.
func createIPNCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(IPNCRDName)

	return crdhelpers.CreateUpdateCRD(
		clientset,
		constructV1CRD(k8sconstv1alpha1.IPNName, ciliumCRD),
		crdhelpers.NewDefaultPoller(),
		k8sconst.CustomResourceDefinitionSchemaVersionKey,
		versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
	)
}

// createMulticastGroupCRD creates and updates the IsovalentMulticastGroup CRD.
func createMulticastGroupCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(MulticastGroupCRDName)

	return crdhelpers.CreateUpdateCRD(
		clientset,
		constructV1CRD(k8sconstv1alpha1.MulticastGroupName, ciliumCRD),
		crdhelpers.NewDefaultPoller(),
		k8sconst.CustomResourceDefinitionSchemaVersionKey,
		versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
	)
}

// createMulticastNodeCRD creates and updates the IsovalentMulticastNode CRD.
func createMulticastNodeCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(MulticastNodeCRDName)

	return crdhelpers.CreateUpdateCRD(
		clientset,
		constructV1CRD(k8sconstv1alpha1.MulticastNodeName, ciliumCRD),
		crdhelpers.NewDefaultPoller(),
		k8sconst.CustomResourceDefinitionSchemaVersionKey,
		versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
	)
}

// createIsovalentMeshEndpointCRD creates and updates the IsovalentMeshEndpoint CRD.
func createIsovalentMeshEndpointCRD(clientset apiextensionsclient.Interface) error {
	ciliumCRD := GetPregeneratedCRD(IsovalentMeshEndpointCRDName)

	return crdhelpers.CreateUpdateCRD(
		clientset,
		constructV1CRD(k8sconstv1alpha1.IsovalentMeshEndpointName, ciliumCRD),
		crdhelpers.NewDefaultPoller(),
		k8sconst.CustomResourceDefinitionSchemaVersionKey,
		versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion),
	)
}

func constructV1CRD(
	name string,
	template apiextensionsv1.CustomResourceDefinition,
) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				k8sconst.CustomResourceDefinitionSchemaVersionKey: k8sconst.CustomResourceDefinitionSchemaVersion,
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: k8sconst.CustomResourceDefinitionGroup,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:       template.Spec.Names.Kind,
				Plural:     template.Spec.Names.Plural,
				ShortNames: template.Spec.Names.ShortNames,
				Singular:   template.Spec.Names.Singular,
			},
			Scope:    template.Spec.Scope,
			Versions: template.Spec.Versions,
		},
	}
}

// RegisterCRDs registers all CRDs with the K8s apiserver.
func RegisterCRDs(clientset client.Clientset) error {
	if err := CreateCustomResourceDefinitions(clientset); err != nil {
		return fmt.Errorf("Unable to create custom resource definition: %w", err)
	}

	return nil
}
