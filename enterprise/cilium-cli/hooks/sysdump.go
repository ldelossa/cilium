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
	"regexp"
	"strings"

	enterpriseSysdump "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/sysdump"
	enterpriseFeatures "github.com/isovalent/cilium/enterprise/cilium-cli/hooks/utils/features"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/cilium-cli/sysdump"
)

const (
	enterpriseLabelSelector      = "app.kubernetes.io/name=hubble-enterprise"
	enterpriseAgentContainerName = "enterprise"
	enterpriseBugtoolPrefix      = "hubble-enterprise-bugtool"
	enterpriseCLICommand         = "hubble-enterprise"
)

var (
	fluentdAWSKeyIDRegexp     *regexp.Regexp
	fluentdAWSSecretKeyRegexp *regexp.Regexp
)

func init() {
	fluentdAWSKeyIDRegexp = regexp.MustCompile(`(aws_key_id).*`)
	fluentdAWSSecretKeyRegexp = regexp.MustCompile(`(aws_sec_key).*`)
}

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
			Description:     "Collect hubble-relay rbac policies",
			Quick:           true,
			Task: func(ctx context.Context) error {
				cm := "hubble-rbac-policy"
				configMap, err := collector.Client.GetConfigMap(ctx, collector.Options.CiliumNamespace, cm, metav1.GetOptions{})
				if kerrors.IsNotFound(err) {
					// Ignore not found. Might not be enabled or we're looking at the wrong namespace
					return nil
				}
				if err != nil {
					return fmt.Errorf("failed to get Hubble Relay RBAC policy configmap: %w", err)
				}
				if err := collector.WriteYAML(fmt.Sprintf("%s-<ts>.yaml", cm), configMap); err != nil {
					return fmt.Errorf("failed to collect Hubble Relay RBAC policy configmap: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Timescape Helm values",
			Quick:           true,
			Task: func(ctx context.Context) error {
				namespaces := []string{collector.Options.CiliumNamespace}
				if opts.HubbleTimescapeNamespace != collector.Options.CiliumNamespace {
					namespaces = append(namespaces, opts.HubbleTimescapeNamespace)
				}

				var taskErr error
				for _, ns := range namespaces {
					val, err := collector.Client.GetHelmValues(ctx, opts.HubbleTimescapeReleaseName, ns)
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-timescape helm values from namespace %q: %w", ns, err))
						continue
					}
					if err := collector.WriteString("hubble-timescape-helm-values-<ts>.yaml", val); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-timescape helm values from namespace %q: %w", ns, err))
						continue
					}
					// we didn't hit any errors, return early with the successful values
					return nil
				}
				return taskErr
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Timescape configmaps",
			Quick:           true,
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
			Description:     "Collecting bugtool output from 'hubble-timescape' pods",
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
						return fmt.Errorf("failed to get bugtool info from 'hubble-timescape' pods")
					}
					pods.Items = append(pods.Items, p.Items...)
				}
				if err = enterpriseSysdump.SubmitTimescapeBugtoolTasks(
					collector,
					sysdump.FilterPods(pods, collector.NodeList),
					"hubble-timescape-bugtool",
					opts.HubbleTimescapeBugtoolFlags,
				); err != nil {
					return fmt.Errorf("error collecting bugtool output from 'hubble-timescape' pods: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'hubble-ui' enterprise pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				namespaces := []string{opts.HubbleUINamespace, collector.Options.CiliumNamespace}

				var taskErr error
				for _, ns := range namespaces {
					p, err := collector.Client.ListPods(ctx, ns, metav1.ListOptions{
						LabelSelector: collector.Options.HubbleUILabelSelector,
					})
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to get logs from '%s/hubble-ui' pods: %w", ns, err))
						continue
					}
					if err = collector.SubmitLogsTasks(sysdump.FilterPods(p, collector.NodeList),
						collector.Options.LogsSinceTime, collector.Options.LogsLimitBytes); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect logs from '%s/hubble-ui' pods: %w", ns, err))
						continue
					}
					// we didn't hit any errors, return early with the successful logs
					return nil
				}
				return taskErr
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
			Quick:           true,
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
			Description:     "Collecting Hubble UI Enterprise oauth2-proxy Configmap",
			Quick:           true,
			Task: func(ctx context.Context) error {
				namespaces := []string{opts.HubbleUINamespace, collector.Options.CiliumNamespace}
				var taskErr error
				for _, ns := range namespaces {
					configMap, err := collector.Client.GetConfigMap(ctx, ns, "oauth2-proxy", metav1.GetOptions{})
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to get Hubble UI Enterprise '%s/oauth2-proxy' Configmap: %w", ns, err))
						continue
					}
					if err := collector.WriteYAML("hubble-enterprise-oauth2-proxy-configmap-<ts>.yaml", configMap); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to get Hubble UI Enterprise '%s/oauth2-proxy' Configmap: %w", ns, err))
						continue
					}
					// we didn't hit any errors, return early with the successful config
					return nil
				}
				return taskErr
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Enterprise Configmap",
			Quick:           true,
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
			CreatesSubtasks: true,
			Description:     "Collect hubble-enterprise fluentd-export configmap",
			Quick:           true,
			Task: func(ctx context.Context) error {
				namespaces := []string{opts.HubbleEnterpriseNamespace}

				var taskErr error
				for _, ns := range namespaces {
					cm := "hubble-enterprise-export-fluentd"
					configMap, err := collector.Client.GetConfigMap(ctx, ns, cm, metav1.GetOptions{})
					if kerrors.IsNotFound(err) {
						// Ignore not found. Might not be enabled or we're looking at the wrong namespace
						return nil
					}
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect %s configmap from namespace %q: %w", cm, ns, err))
						continue
					}

					// DeepCopy before mutating
					configMap = configMap.DeepCopy()
					// Sanitize any potentially hardcoded AWS creds in the Config
					for k, v := range configMap.Data {
						configMap.Data[k] = sanitizeHardcodedFluentdS3Creds(v)
					}
					if err := collector.WriteYAML(fmt.Sprintf("%s-configmap-<ts>.yaml", cm), configMap); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect %s configmap from namespace %q: %w", cm, ns, err))
						continue
					}
					return nil
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble Enterprise Helm values",
			Quick:           true,
			Task: func(ctx context.Context) error {
				namespaces := []string{opts.HubbleEnterpriseNamespace}

				var taskErr error
				for _, ns := range namespaces {
					val, err := collector.Client.GetHelmValues(ctx, opts.HubbleEnterpriseReleaseName, ns)
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-enterprise helm values from namespace %q: %w", ns, err))
						continue
					}

					var data map[string]any
					if err := yamlutil.Unmarshal([]byte(val), &data); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-enterprise helm values from namespace %q: %w", ns, err))
						continue
					}

					// sanitize tls related options. Private keys in are especially
					// important to avoid collecting, but we skip other fields in case
					// the user made a mistake configuring.
					sanitizeRBACTLSOptions(data)
					// sanitize fluentd AWS output in-case the user hard-coded creds in there
					sanitizeFluentdAWSCreds(data)

					b, err := yaml.Marshal(data)
					if err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-enterprise helm values from namespace %q: %w", ns, err))
						continue
					}
					val = string(b)

					if err := collector.WriteString("hubble-enterprise-helm-values-<ts>.yaml", val); err != nil {
						taskErr = errors.Join(taskErr, fmt.Errorf("failed to collect hubble-enterprise helm values from namespace %q: %w", ns, err))
						continue
					}
					// we didn't hit any errors, return early with the successful values
					return nil
				}
				return taskErr
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
		{
			CreatesSubtasks: true,
			Description:     "Collecting all Custom Resource Definitions (CRDs)",
			Quick:           true,
			Task: func(ctx context.Context) error {
				crdGVR := schema.GroupVersionResource{
					Group:    "apiextensions.k8s.io",
					Version:  "v1",
					Resource: "customresourcedefinitions",
				}
				n := corev1.NamespaceAll
				crdList, err := collector.Client.ListUnstructured(ctx, crdGVR, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to list CRDs: %w", err)
				}
				if err := collector.WriteYAML("k8s-crds-<ts>.yaml", crdList); err != nil {
					return fmt.Errorf("failed to write CRD list to YAML file: %w", err)
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

	if collector.FeatureSet[enterpriseFeatures.EnterpriseBGPControlPlane].Enabled {
		addEnterpriseBGPSysdumpTasks(collector)
	}

	if collector.FeatureSet[enterpriseFeatures.BFD].Enabled {
		addEnterpriseBFDSysdumpTasks(collector)
	}

	return nil
}

func addSRv6SysdumpTasks(collector *sysdump.Collector) {
	collector.AddTasks([]sysdump.Task{
		collectIsovalentV1Alpha1Resource(collector, "IsovalentVRF", "isovalentvrfs"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentSRv6EgressPolicy", "isovalentsrv6egresspolicies"),

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
		collectIsovalentV1Alpha1Resource(collector, "IsovalentSRv6SIDManager", "isovalentsrv6sidmanagers"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentSRv6LocatorPool", "isovalentsrv6locatorpools"),
	})
}

func addEnterpriseBGPSysdumpTasks(collector *sysdump.Collector) {
	collector.AddTasks([]sysdump.Task{
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBGPClusterConfig", "isovalentbgpclusterconfigs"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBGPPeerConfig", "isovalentbgppeerconfigs"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBGPAdvertisement", "isovalentbgpadvertisements"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBGPNodeConfig", "isovalentbgpnodeconfigs"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBGPNodeConfigOverride", "isovalentbgpnodeconfigoverrides"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBGPVRFConfig", "isovalentbgpvrfconfigs"),
	})
}

func addEnterpriseBFDSysdumpTasks(collector *sysdump.Collector) {
	collector.AddTasks([]sysdump.Task{
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBFDProfile", "isovalentbfdprofiles"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBFDNodeConfig", "isovalentbfdnodeconfigs"),
		collectIsovalentV1Alpha1Resource(collector, "IsovalentBFDNodeConfigOverride", "isovalentbfdnodeconfigoverrides"),
	})
}

func collectIsovalentV1Alpha1Resource(collector *sysdump.Collector, kind, name string) sysdump.Task {
	return sysdump.Task{
		Description: fmt.Sprintf("Collecting %s", kind),
		Quick:       true,
		Task: func(ctx context.Context) error {
			gvr := schema.GroupVersionResource{
				Group:    "isovalent.com",
				Resource: name,
				Version:  "v1alpha1",
			}
			n := corev1.NamespaceAll
			v, err := collector.Client.ListUnstructured(ctx, gvr, &n, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("failed to collect %s: %w", kind, err)
			}
			if err := collector.WriteYAML(fmt.Sprintf("cilium-enterprise-%s-<ts>.yaml", name), v); err != nil {
				return fmt.Errorf("failed to collect %s: %w", kind, err)
			}
			return nil
		},
	}
}

func setMapValueIfExists(m map[string]any, path string, val any) {
	keys := strings.Split(path, ".")
	for i, key := range keys {
		if i == len(keys)-1 {
			if _, exists := m[key]; exists {
				m[key] = val
			}
			return
		}
		m2, ok := m[key]
		if !ok {
			return
		}
		m3, ok := m2.(map[string]any)
		if !ok {
			return
		}
		m = m3
	}
}

func getMapValueIfExists(m map[string]any, path string) (any, bool) {
	keys := strings.Split(path, ".")
	for i, key := range keys {
		if i == len(keys)-1 {
			val, ok := m[key]
			return val, ok
		}
		m2, ok := m[key]
		if !ok {
			return nil, false
		}
		m3, ok := m2.(map[string]any)
		if !ok {
			return nil, false
		}
		m = m3
	}
	return nil, false
}

func sanitizeRBACTLSOptions(data map[string]any) {
	setMapValueIfExists(data, "rbac.metricsProxy.oidcCert", "xxx")
	setMapValueIfExists(data, "rbac.metricsProxy.tlsKey", "xxx")
	setMapValueIfExists(data, "rbac.metricsProxy.cert", "xxx")
	setMapValueIfExists(data, "rbac.metricsProxy.clientCA", "xxx")
	setMapValueIfExists(data, "rbac.observerProxy.oidcCert", "xxx")
	setMapValueIfExists(data, "rbac.observerProxy.tlsKey", "xxx")
	setMapValueIfExists(data, "rbac.observerProxy.cert", "xxx")
	setMapValueIfExists(data, "rbac.observerProxy.clientCA", "xxx")
}

func sanitizeFluentdAWSCreds(data map[string]any) {
	var fluentdOutput string
	if output, ok := getMapValueIfExists(data, "export.fluentd.output"); ok {
		outputStr, ok := output.(string)
		if !ok {
			return
		}
		fluentdOutput = outputStr
	}

	fluentdOutput = sanitizeHardcodedFluentdS3Creds(fluentdOutput)

	setMapValueIfExists(data, "export.fluentd.output", fluentdOutput)
}

func sanitizeHardcodedFluentdS3Creds(s string) string {
	for _, re := range []*regexp.Regexp{fluentdAWSKeyIDRegexp, fluentdAWSSecretKeyRegexp} {
		s = re.ReplaceAllString(s, "$1 xxx")
	}
	return s
}
