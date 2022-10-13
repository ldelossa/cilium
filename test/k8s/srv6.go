// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"context"
	"fmt"

	. "github.com/onsi/gomega"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = SkipDescribeIf(helpers.DoesNotExistNodeWithoutCilium, "K8sSRv6", func() {
	var (
		k               *helpers.Kubectl
		ciliumFilename  string
		k8s1NodeName    string
		k8s2NodeName    string
		outsideNodeName string
		k8s1IP          string
		k8s2IP          string
		outsideNodeIP   string
	)

	const (
		compilerPodName = "srv6-compiler"
		testPodFilter   = "zgroup=testDS"
		testPodName     = "testds"
	)

	BeforeAll(func() {
		k = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		deploymentManager.SetKubectl(k)

		k8s1NodeName, k8s1IP = k.GetNodeInfo(helpers.K8s1)
		k8s2NodeName, k8s2IP = k.GetNodeInfo(helpers.K8s2)
		outsideNodeName, outsideNodeIP = k.GetNodeInfo(k.GetFirstNodeWithoutCiliumLabel())

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumOptionsAndDNS(k, ciliumFilename, map[string]string{
			"srv6.enabled":           "true",
			"bpf.monitorAggregation": "none",
		})
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(k, ciliumFilename)
	})

	installK8s3Routes := func() {
		var cn1 cilium_v2.CiliumNode
		err := k.Get(helpers.DefaultNamespace, fmt.Sprintf("ciliumnode %s", k8s1NodeName)).Unmarshal(&cn1)
		Expect(err).Should(BeNil(), "Can not retrieve %s CiliumNode %s", k8s1NodeName)

		var cn2 cilium_v2.CiliumNode
		err = k.Get(helpers.DefaultNamespace, fmt.Sprintf("ciliumnode %s", k8s2NodeName)).Unmarshal(&cn2)
		Expect(err).Should(BeNil(), "Can not retrieve %s CiliumNode %s", k8s2NodeName)

		res := k.AddIPRoute(outsideNodeName, cn1.Spec.IPAM.PodCIDRs[0], k8s1IP, true)
		Expect(res).Should(helpers.CMDSuccess(), "Error adding pod CIDR IP route for %s", k8s1NodeName)
		res = k.AddIPRoute(outsideNodeName, cn2.Spec.IPAM.PodCIDRs[0], k8s2IP, true)
		Expect(res).Should(helpers.CMDSuccess(), "Error adding pod CIDR IP route for %s", k8s2NodeName)
	}

	It("SRv6 encapsulation", func() {
		srv6YAML := helpers.ManifestGet(k.BasePath(), "srv6.yaml")
		k.Create(srv6YAML).ExpectSuccess("Unable to create resource %q", srv6YAML)

		err := k.WaitForSinglePod(helpers.DefaultNamespace, compilerPodName, helpers.HelperTimeout)
		Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("%s pod not ready after timeout", compilerPodName))

		cmds := []string{
			"clang -O2 -Wall -target bpf -c test/srv6/srv6_decap_encap.c -o test/srv6/srv6_decap_encap.o",
			"tc qdisc add dev enp0s8 clsact",
			"tc filter replace dev enp0s8 ingress pref 1 handle 1 bpf da obj test/srv6/srv6_decap_encap.o sec decap",
			"tc filter replace dev enp0s8 egress pref 1 handle 1 bpf da obj test/srv6/srv6_decap_encap.o sec encap",
		}
		for _, cmd := range cmds {
			k.ExecPodCmd(helpers.DefaultNamespace, compilerPodName, cmd).ExpectSuccess("Failed to run command %s", cmd)
		}

		installK8s3Routes()

		testPodsIPs, err := k.GetPodsIPs(helpers.DefaultNamespace, testPodFilter)
		Expect(err).Should(BeNil(), "Cannot retrieve pod IPs for %s", testPodFilter)
		res := k.ExecInHostNetNS(context.TODO(), outsideNodeName, helpers.CurlFail("http://%s/", testPodsIPs["testds"]))
		Expect(res).Should(helpers.CMDSuccess(), "Failed to connect to %s from %s", testPodsIPs["testds"], outsideNodeName)

		res = k.ExecPodCmd(helpers.DefaultNamespace, testPodName, helpers.CurlFail("http://%s/", outsideNodeIP))
		Expect(res).Should(helpers.CMDSuccess(), "Failed to connect to %s from %s", outsideNodeIP, testPodName)
	})
})
