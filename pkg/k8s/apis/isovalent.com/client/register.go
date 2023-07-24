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
)

// log is the k8s package logger object.
var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsysK8s)

type crdCreationFn func(clientset apiextensionsclient.Interface) error

// CreateCustomResourceDefinitions creates our CRD objects in the Kubernetes
// cluster.
func CreateCustomResourceDefinitions(clientset apiextensionsclient.Interface) error {
	g, _ := errgroup.WithContext(context.Background())

	resourceToCreateFnMapping := map[string]crdCreationFn{
		synced.CRDResourceName(k8sconstv1alpha1.IFGName): createIFGCRD,
		synced.CRDResourceName(k8sconstv1.IEGPName):      createIEGPCRD,
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

	//go:embed crds/v1/isovalentegressgatewaypolicies.yaml
	crdsv1IsovalentEgressGatewayPolicies []byte
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
	case IEGPCRDName:
		crdBytes = crdsv1IsovalentEgressGatewayPolicies
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
			Group: k8sconstv1alpha1.CustomResourceDefinitionGroup,
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
		return fmt.Errorf("Unable to create custom resource definition: %s", err)
	}

	return nil
}
