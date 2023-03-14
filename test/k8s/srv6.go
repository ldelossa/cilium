// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"context"
	"fmt"
	"net"

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
			"srv6.encapMode":         "srh",
			"bpf.monitorAggregation": "none",
		})
	})

	AfterAll(func() {
		srv6YAML := helpers.ManifestGet(k.BasePath(), "srv6.yaml")
		k.Delete(srv6YAML)
		ExpectAllPodsTerminated(k)

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

	plumbEndDTRule := func(nodeName string) {
		privateIface, err := k.GetPrivateIface(nodeName)
		Expect(err).Should(BeNil(), "Cannot retrieve iface of node %s", nodeName)

		nodeIPv6, err := helpers.GetIPv6AddrForIface(k, nodeName, privateIface)
		Expect(err).Should(BeNil(), "Cannot retrieve IPv6 of node %s", nodeName)

		ip := []byte(net.ParseIP(nodeIPv6))
		cmd := "bpftool map update pinned /sys/fs/bpf/tc/globals/cilium_srv6_sid key"
		for _, b := range ip {
			cmd = fmt.Sprintf("%s 0x%x", cmd, b)
		}
		cmd = fmt.Sprintf("%s value 0x0c 00 00 00", cmd)
		fmt.Println(cmd)

		ciliumPod, err := k.GetCiliumPodOnNode(helpers.K8s1)
		Expect(err).Should(BeNil(), "Cannot determine cilium pod name")
		res := k.CiliumExecContext(context.TODO(), ciliumPod, cmd)
		res.ExpectSuccess("Failed to run command %s", cmd)
	}

	It("SRv6 encapsulation", func() {
		srv6YAML := helpers.ManifestGet(k.BasePath(), "srv6.yaml")
		k.Create(srv6YAML).ExpectSuccess("Unable to create resource %q", srv6YAML)

		err := k.WaitForSinglePod(helpers.DefaultNamespace, compilerPodName, helpers.HelperTimeout)
		Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("%s pod not ready after timeout", compilerPodName))

		cmds := []string{
			"clang -O2 -Wall -target bpf -c test/srv6/srv6_decap_encap.c -o test/srv6/srv6_decap_encap.o",
			"tc qdisc replace dev enp0s8 clsact",
			"tc filter replace dev enp0s8 ingress pref 1 handle 1 bpf da obj test/srv6/srv6_decap_encap.o sec decap",
			"tc filter replace dev enp0s8 egress pref 1 handle 1 bpf da obj test/srv6/srv6_decap_encap.o sec encap",
		}
		for _, cmd := range cmds {
			k.ExecPodCmd(helpers.DefaultNamespace, compilerPodName, cmd).ExpectSuccess("Failed to run command %s", cmd)
		}

		installK8s3Routes()

		// We need to manually teach k8s1's datapath about the expected SID for
		// End.DT{4,6} on ingress. This is because, when running SRv6 without
		// the BGP integration, we don't populate the SID map. It needs a proper
		// fix longer term (or we drop CRDs) but for now let's just fixup the
		// test since the BGP integration is what users are expected to run.
		// Note we can hardcode k8s1 here because we know the client pod always
		// runs on k8s1 (see manifest.). The VRF ID is hardcoded as well, for
		// the same reason.
		plumbEndDTRule(k8s1NodeName)

		testPodsIPs, err := k.GetPodsIPs(helpers.DefaultNamespace, testPodFilter)
		Expect(err).Should(BeNil(), "Cannot retrieve pod IPs for %s", testPodFilter)
		res := k.ExecInHostNetNS(context.TODO(), outsideNodeName, helpers.CurlFail("http://%s/", testPodsIPs["testds"]))
		Expect(res).Should(helpers.CMDSuccess(), "Failed to connect to %s from %s", testPodsIPs["testds"], outsideNodeName)

		res = k.ExecPodCmd(helpers.DefaultNamespace, testPodName, helpers.CurlFail("http://%s/", outsideNodeIP))
		Expect(res).Should(helpers.CMDSuccess(), "Failed to connect to %s from %s", outsideNodeIP, testPodName)
	})
})
