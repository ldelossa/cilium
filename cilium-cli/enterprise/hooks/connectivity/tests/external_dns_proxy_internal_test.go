//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package tests

import (
	"cmp"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	enterpriseDefaults "github.com/cilium/cilium/cilium-cli/enterprise/defaults"
)

func TestExternalCiliumDNSProxySource(t *testing.T) {
	ciliumDNSProxyPod := check.Pod{
		Pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cilium-dnsproxy-t5j79",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: enterpriseDefaults.ExternalCiliumDNSProxyName,
						Args: []string{"--expose-metrics", "--prometheus-port=99675"},
					},
				},
			},
		},
	}

	podWithPrometheusMissing := check.Pod{
		Pod: &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cilium-dnsproxy-lm2xk",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: enterpriseDefaults.ExternalCiliumDNSProxyName,
						Args: []string{"--expose-metrics"},
					},
				},
			},
		},
	}

	tests := map[string]struct {
		dnsProxyPods map[string]check.Pod
		want         check.MetricsSource
	}{
		"nominal case": {
			dnsProxyPods: map[string]check.Pod{
				ciliumDNSProxyPod.Pod.Name: ciliumDNSProxyPod,
			},
			want: check.MetricsSource{
				Name: enterpriseDefaults.ExternalCiliumDNSProxyName,
				Pods: []check.Pod{ciliumDNSProxyPod},
				Port: "99675",
			},
		},
		"with two pods": {
			dnsProxyPods: map[string]check.Pod{
				podWithPrometheusMissing.Pod.Name: podWithPrometheusMissing,
				ciliumDNSProxyPod.Pod.Name:        ciliumDNSProxyPod,
			},
			want: check.MetricsSource{
				Name: enterpriseDefaults.ExternalCiliumDNSProxyName,
				Pods: []check.Pod{podWithPrometheusMissing, ciliumDNSProxyPod},
				Port: "99675",
			},
		},
		"no cilium dns proxy pods": {
			dnsProxyPods: map[string]check.Pod{},
			want:         check.MetricsSource{},
		},
		"no prometheus container port": {
			dnsProxyPods: map[string]check.Pod{enterpriseDefaults.ExternalCiliumDNSProxyName: podWithPrometheusMissing},
			want:         check.MetricsSource{},
		},
	}

	sortPods := func(a, b check.Pod) int {
		return cmp.Compare(a.Name(), b.Name())
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := ExternalCiliumDNSProxySource(tc.dnsProxyPods)
			slices.SortFunc(got.Pods, sortPods)
			want := tc.want
			slices.SortFunc(want.Pods, sortPods)
			assert.Equal(t, want, got)
		})
	}
}
