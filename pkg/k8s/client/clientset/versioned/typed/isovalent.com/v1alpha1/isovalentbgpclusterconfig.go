// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"

	v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// IsovalentBGPClusterConfigsGetter has a method to return a IsovalentBGPClusterConfigInterface.
// A group's client should implement this interface.
type IsovalentBGPClusterConfigsGetter interface {
	IsovalentBGPClusterConfigs() IsovalentBGPClusterConfigInterface
}

// IsovalentBGPClusterConfigInterface has methods to work with IsovalentBGPClusterConfig resources.
type IsovalentBGPClusterConfigInterface interface {
	Create(ctx context.Context, isovalentBGPClusterConfig *v1alpha1.IsovalentBGPClusterConfig, opts v1.CreateOptions) (*v1alpha1.IsovalentBGPClusterConfig, error)
	Update(ctx context.Context, isovalentBGPClusterConfig *v1alpha1.IsovalentBGPClusterConfig, opts v1.UpdateOptions) (*v1alpha1.IsovalentBGPClusterConfig, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.IsovalentBGPClusterConfig, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.IsovalentBGPClusterConfigList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IsovalentBGPClusterConfig, err error)
	IsovalentBGPClusterConfigExpansion
}

// isovalentBGPClusterConfigs implements IsovalentBGPClusterConfigInterface
type isovalentBGPClusterConfigs struct {
	*gentype.ClientWithList[*v1alpha1.IsovalentBGPClusterConfig, *v1alpha1.IsovalentBGPClusterConfigList]
}

// newIsovalentBGPClusterConfigs returns a IsovalentBGPClusterConfigs
func newIsovalentBGPClusterConfigs(c *IsovalentV1alpha1Client) *isovalentBGPClusterConfigs {
	return &isovalentBGPClusterConfigs{
		gentype.NewClientWithList[*v1alpha1.IsovalentBGPClusterConfig, *v1alpha1.IsovalentBGPClusterConfigList](
			"isovalentbgpclusterconfigs",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *v1alpha1.IsovalentBGPClusterConfig { return &v1alpha1.IsovalentBGPClusterConfig{} },
			func() *v1alpha1.IsovalentBGPClusterConfigList { return &v1alpha1.IsovalentBGPClusterConfigList{} }),
	}
}
