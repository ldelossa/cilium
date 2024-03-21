//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package hooks

import (
	"context"
	"errors"
	"fmt"

	enterpriseFeatures "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/utils/features"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium-cli/sysdump"
)

const (
	enterpriseLabelSelector      = "app.kubernetes.io/name=hubble-enterprise"
	enterpriseAgentContainerName = "enterprise"
	enterpriseBugtoolPrefix      = "hubble-enterprise-bugtool"
	enterpriseCLICommand         = "hubble-enterprise"
)

func addSysdumpTasks(collector *sysdump.Collector, opts *EnterpriseOptions) error {
	collector.AddTasks([]sysdump.Task{
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'hubble-enterprise' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: enterpriseLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from 'hubble-enterprise' pods")
				}
				if err = collector.SubmitLogsTasks(sysdump.FilterPods(p, collector.NodeList),
					collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'hubble-enterprise' pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting bugtool output from 'hubble-enterprise' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: enterpriseLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get 'hubble-enterprise' pods")
				}
				if err = collector.SubmitTetragonBugtoolTasks(sysdump.FilterPods(p, collector.NodeList),
					enterpriseAgentContainerName, enterpriseBugtoolPrefix, enterpriseCLICommand); err != nil {
					return fmt.Errorf("failed to collect bugtool output from 'hubble-enterprise' pods: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Timescape Helm values",
			Quick:           false,
			Task: func(ctx context.Context) error {
				namespaces := []string{collector.Options.CiliumNamespace}
				if opts.HubbleTimescapeNamespace != collector.Options.CiliumNamespace {
					namespaces = append(namespaces, opts.HubbleTimescapeNamespace)
				}

				var taskErr error
				for _, ns := range namespaces {
					val, err := collector.Client.GetHelmValues(ctx, opts.HubbleTimescapeReleaseName, ns)
					if err != nil {
						taskErr = errors.Join(taskErr, err)
					}
					if val != "" {
						if err := collector.WriteString("hubble-timescape-helm-values-<ts>.yaml", val); err != nil {
							return fmt.Errorf("failed to collect hubble-timescape helm values")
						}
						return nil
					}
				}
				return fmt.Errorf("failed to collect hubble-timescape helm values")
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Timescape configmaps",
			Quick:           false,
			Task: func(ctx context.Context) error {
				namespaces := []string{collector.Options.CiliumNamespace}
				if opts.HubbleTimescapeNamespace != collector.Options.CiliumNamespace {
					namespaces = append(namespaces, opts.HubbleTimescapeNamespace)
				}
				configMaps := []string{
					"hubble-timescape-clickhouse-client-config",
					"hubble-timescape-ingester-config",
					"hubble-timescape-migrate-config",
					"hubble-timescape-rbac-policy",
					"hubble-timescape-server-config",
				}

				for _, ns := range namespaces {
					for _, cm := range configMaps {
						configMap, err := collector.Client.GetConfigMap(ctx, ns, cm, metav1.GetOptions{})
						if kerrors.IsNotFound(err) {
							// Ignore not found. Might not be enabled or we're looking at the wrong namespace
							continue
						}
						if err != nil {
							return fmt.Errorf("failed to get Hubble Timescape configmaps: %w", err)
						}
						if err := collector.WriteYAML(fmt.Sprintf("%s-<ts>.yaml", cm), configMap); err != nil {
							return fmt.Errorf("failed to collect Hubble Timescape configmaps: %w", err)
						}
					}
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'hubble-timescape' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				pods := &corev1.PodList{}
				var err error

				namespaces := []string{collector.Options.CiliumNamespace}
				if opts.HubbleTimescapeNamespace != collector.Options.CiliumNamespace {
					namespaces = append(namespaces, opts.HubbleTimescapeNamespace)
				}

				for _, ns := range namespaces {
					p, err := collector.Client.ListPods(ctx, ns, metav1.ListOptions{
						LabelSelector: opts.HubbleTimescapeSelector,
					})
					if err != nil {
						return fmt.Errorf("failed to get logs from 'hubble-timescape' pods")
					}
					pods.Items = append(pods.Items, p.Items...)
				}
				if err = collector.SubmitLogsTasks(sysdump.FilterPods(pods, collector.NodeList),
					collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'hubble-timescape' pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'hubble-ui' enterprise pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, opts.HubbleUINamespace, metav1.ListOptions{
					LabelSelector: collector.Options.HubbleUILabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from 'hubble-ui' pods")
				}
				if err = collector.SubmitLogsTasks(sysdump.FilterPods(p, collector.NodeList),
					collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'hubble-ui' pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'cilium-dnsproxy' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := collector.Client.ListPods(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: "k8s-app=cilium-dnsproxy",
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from 'cilium-dnsproxy' pods")
				}
				if err = collector.SubmitLogsTasks(sysdump.FilterPods(p, collector.NodeList),
					collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'cilium-dnsproxy' pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting DNS Proxy Daemonset",
			Quick:           false,
			Task: func(ctx context.Context) error {
				daemonSets, err := collector.Client.ListDaemonSet(ctx, collector.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: "k8s-app=cilium-dnsproxy",
				})
				if err != nil {
					return fmt.Errorf("failed to get Cilium DNS Daemonset")
				}
				if err := collector.WriteYAML("cilium-enterprise-dns-proxy-daemonset-<ts>.yaml", daemonSets); err != nil {
					return fmt.Errorf("failed to collect DNS Proxy Daemonset: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Auth Configmap",
			Quick:           false,
			Task: func(ctx context.Context) error {
				configMap, err := collector.Client.GetConfigMap(ctx, collector.Options.CiliumNamespace, "oauth2-proxy", metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get Hubble Auth Configmap")
				}
				if err := collector.WriteYAML("hubble-enterprise-oauth-configmap-<ts>.yaml", configMap); err != nil {
					return fmt.Errorf("failed to collect Hubble Enterprise Oauth Configmap: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Enterprise Configmap",
			Quick:           false,
			Task: func(ctx context.Context) error {
				configMap, err := collector.Client.GetConfigMap(ctx, collector.Options.CiliumNamespace, "hubble-enterprise-config", metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get Hubble Enterprise configmap")
				}
				if err := collector.WriteYAML("hubble-enterprise-configmap-<ts>.yaml", configMap); err != nil {
					return fmt.Errorf("failed to collect Hubble Enterprise configmap: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentVRF",
			Quick:       true,
			Task: func(ctx context.Context) error {
				locatorPools := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentvrfs",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, locatorPools, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent VRFs: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentvrfs-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent VRFs: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentSRv6EgressPolicy",
			Quick:       true,
			Task: func(ctx context.Context) error {
				locatorPools := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentsrv6egresspolicies",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, locatorPools, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 Egress Policies: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentsrv6egresspolicies-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 Egress Policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentFQDNGroup",
			Quick:       true,
			Task: func(ctx context.Context) error {
				fqdnGroups := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentfqdngroups",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, fqdnGroups, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent FQDN groups: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentfqdngroups-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent FQDN groups: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentPodNetworks",
			Quick:       true,
			Task: func(ctx context.Context) error {
				podNetworks := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentpodnetworks",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, podNetworks, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent pod networks: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentpodnetworks-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent pod networks: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentSRv6SIDManager",
			Quick:       true,
			Task: func(ctx context.Context) error {
				sidManagers := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentsrv6sidmanagers",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, sidManagers, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 SID Managers: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentsrv6sidmanagers-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 SID Managers: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentSRv6LocatorPool",
			Quick:       true,
			Task: func(ctx context.Context) error {
				locatorPools := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentsrv6locatorpools",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, locatorPools, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 Locator Pools: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentsrv6locatorpools-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 Locator Pools: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentEgressGatewayPolicy",
			Quick:       true,
			Task: func(ctx context.Context) error {
				gatewayPolicies := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentegressgatewaypolicies",
					Version:  "v1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, gatewayPolicies, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent Egress Gateway policies: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentegressgatewaypolicies-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent Egress Gateway policies: %w", err)
				}
				return nil
			},
		},
		{
			// collect raw output to pick up HA-style format
			Description: "Collecting CiliumEgressGatewayPolicy",
			Quick:       true,
			Task: func(ctx context.Context) error {
				gatewayPolicies := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "ciliumegressgatewaypolicies",
					Version:  "v2",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, gatewayPolicies, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium Egress Gateway policies: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-ciliumegressgatewaypolicies-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Cilium Egress Gateway policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentMulticastGroup",
			Quick:       true,
			Task: func(ctx context.Context) error {
				multicastGroups := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentmulticastgroups",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, multicastGroups, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent Multicast Groups: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentmulticastgroups-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent Multicast Groups: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentMulticastNodes",
			Quick:       true,
			Task: func(ctx context.Context) error {
				multicastNodes := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentmulticastnodes",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, multicastNodes, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent Multicast Nodes: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentmulticastnodes-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent Multicast Nodes: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Tetragon SandboxPolicies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				sandboxpolicies := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "sandboxpolicies",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, sandboxpolicies, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Tetragon SandboxPolicies: %w", err)
				}
				if err := collector.WriteYAML("tetragon-enterprise-sandboxpolicies-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to write Tetragon SandboxPolicies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Tetragon SandboxPoliciesNamespaced",
			Quick:       true,
			Task: func(ctx context.Context) error {
				sandboxpolicies := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "sandboxpoliciesnamespaced",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, sandboxpolicies, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Tetragon SandboxPoliciesNamespaced: %w", err)
				}
				if err := collector.WriteYAML("tetragon-enterprise-sandboxpoliciesnamespaced-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to write Tetragon SandboxPoliciesNamespaced: %w", err)
				}
				return nil
			},
		},
	})

	if collector.FeatureSet[enterpriseFeatures.SRv6].Enabled {
		addSRv6SysdumpTasks(collector)
	}

	if collector.FeatureSet[enterpriseFeatures.SRv6LocatorPool].Enabled {
		addSRv6LocatorPoolSysdumpTasks(collector)
	}

	return nil
}

func addSRv6SysdumpTasks(collector *sysdump.Collector) {
	collector.AddTasks([]sysdump.Task{
		{
			Description: "Collecting IsovalentVRF",
			Quick:       true,
			Task: func(ctx context.Context) error {
				locatorPools := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentvrfs",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, locatorPools, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent VRFs: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentvrfs-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent VRFs: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentSRv6EgressPolicy",
			Quick:       true,
			Task: func(ctx context.Context) error {
				locatorPools := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentsrv6egresspolicies",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, locatorPools, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 Egress Policies: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentsrv6egresspolicies-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 Egress Policies: %w", err)
				}
				return nil
			},
		},
		// For older versions (<= v1.14-ce)
		{
			Description: "Collecting CiliumSRv6EgressPolicy",
			Quick:       true,
			Task: func(ctx context.Context) error {
				locatorPools := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "ciliumsrv6egresspolicies",
					Version:  "v2alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, locatorPools, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium SRv6 Egress Policies: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-ciliumsrv6egresspolicies-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Cilium SRv6 Egress Policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting CiliumSRv6VRF",
			Quick:       true,
			Task: func(ctx context.Context) error {
				locatorPools := schema.GroupVersionResource{
					Group:    "cilium.io",
					Resource: "ciliumsrv6vrfs",
					Version:  "v2alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, locatorPools, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium SRv6 VRFs: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-ciliumsrv6vrfs-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Cilium SRv6 VRFs: %w", err)
				}
				return nil
			},
		},
	})
}

func addSRv6LocatorPoolSysdumpTasks(collector *sysdump.Collector) {
	collector.AddTasks([]sysdump.Task{
		{
			Description: "Collecting IsovalentSRv6SIDManager",
			Quick:       true,
			Task: func(ctx context.Context) error {
				sidManagers := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentsrv6sidmanagers",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, sidManagers, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 SID Managers: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentsrv6sidmanagers-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 SID Managers: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting IsovalentSRv6LocatorPool",
			Quick:       true,
			Task: func(ctx context.Context) error {
				locatorPools := schema.GroupVersionResource{
					Group:    "isovalent.com",
					Resource: "isovalentsrv6locatorpools",
					Version:  "v1alpha1",
				}
				n := corev1.NamespaceAll
				v, err := collector.Client.ListUnstructured(ctx, locatorPools, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 Locator Pools: %w", err)
				}
				if err := collector.WriteYAML("cilium-enterprise-isovalentsrv6locatorpools-<ts>.yaml", v); err != nil {
					return fmt.Errorf("failed to collect Isovalent SRv6 Locator Pools: %w", err)
				}
				return nil
			},
		},
	})
}
