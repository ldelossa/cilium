//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package multinetwork

import (
	"net"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/models"
	enterpriseModels "github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/plugins/cilium-cni/cmd"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

func Test_DefaultNetwork(t *testing.T) {
	cniParams := cmd.ConfigurationParams{
		Log:  logging.DefaultLogger.WithField("subsys", "multinetwork-cni-test"),
		Conf: &models.DaemonConfigurationStatus{},
		Args: &skel.CmdArgs{
			ContainerID: "container1234",
			IfName:      "eth0",
		},
		CniArgs: &types.ArgsSpec{
			K8S_POD_NAME:      "client",
			K8S_POD_NAMESPACE: "cilium-test",
		},
	}

	networkResponse := &enterpriseModels.NetworkAttachmentList{
		Attachments: []*enterpriseModels.NetworkAttachmentElement{
			{
				Ipam:   &enterpriseModels.NetworkAttachmentIPAMParameters{IpamPool: "default-ipam-pool"},
				Name:   swag.String("default"),
				Routes: nil,
			},
		},
		PodName:      "client",
		PodNamespace: "cilium-test",
	}

	ipamResponse := &models.IPAMResponse{
		Address: &models.AddressPair{
			IPV4:         "10.0.0.10",
			IPV4PoolName: "default-ipam-pool",
			IPV6:         "f00d::10",
			IPV6PoolName: "default-ipam-pool",
		},
		HostAddressing: &models.NodeAddressing{
			IPV4: &models.NodeAddressingElement{
				Enabled: true,
				IP:      "10.0.0.1",
			},
			IPV6: &models.NodeAddressingElement{
				Enabled: true,
				IP:      "f00d::1",
			},
		},
		IPV4: &models.IPAMAddressResponse{
			IP: "10.0.0.10",
		},
		IPV6: &models.IPAMAddressResponse{
			IP: "f00d::10",
		},
	}

	cfgs := constructEndpoints(cniParams, networkResponse)
	assert.Len(t, cfgs, 1)
	assert.Equal(t, "eth0", cfgs[0].IfName())
	assert.Equal(t, "default-ipam-pool", cfgs[0].IPAMPool())
	state, ep, err := cfgs[0].PrepareEndpoint(ipamResponse)
	assert.NoError(t, err)
	assert.Equal(t, &cmd.CmdState{
		HostAddr: ipamResponse.HostAddressing,
	}, state)
	assert.Equal(t, &models.EndpointChangeRequest{
		Addressing:               &models.AddressPair{},
		ContainerID:              "container1234",
		ContainerInterfaceName:   "eth0",
		DatapathConfiguration:    &models.EndpointDatapathConfiguration{},
		Labels:                   models.Labels{},
		K8sPodName:               "client",
		K8sNamespace:             "cilium-test",
		DisableLegacyIdentifiers: false,
		State:                    models.EndpointStateWaitingDashForDashIdentity.Pointer(),
	}, ep)
}

func mustParseIPNet(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipnet
}

func mustParseIP(s string) *net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("failed to parse ip " + s)
	}
	return &ip
}

func Test_ThreeAttachments(t *testing.T) {
	cniParams := cmd.ConfigurationParams{
		Log: logging.DefaultLogger.WithField("subsys", "multinetwork-cni-test"),
		Conf: &models.DaemonConfigurationStatus{
			RouteMTU: 1456,
		},
		Args: &skel.CmdArgs{
			ContainerID: "container1234",
			IfName:      "eth0",
		},
		CniArgs: &types.ArgsSpec{
			K8S_POD_NAME:      "client",
			K8S_POD_NAMESPACE: "cilium-test",
		},
	}

	networkResponse := &enterpriseModels.NetworkAttachmentList{
		Attachments: []*enterpriseModels.NetworkAttachmentElement{
			{
				Ipam: &enterpriseModels.NetworkAttachmentIPAMParameters{IpamPool: "primary-ipam-pool"},
				Name: swag.String("primary"),
				Routes: []*enterpriseModels.NetworkAttachmentRoute{
					{
						Destination: "192.168.0.0/24",
						Gateway:     "192.168.0.1",
					},
				},
			},
			{
				Ipam: &enterpriseModels.NetworkAttachmentIPAMParameters{IpamPool: "secondary-ipam-pool"},
				Name: swag.String("secondary"),
				Routes: []*enterpriseModels.NetworkAttachmentRoute{
					{
						Destination: "172.18.0.0/24",
						Gateway:     "172.18.0.1",
					},
				},
			},
			{
				Ipam:   &enterpriseModels.NetworkAttachmentIPAMParameters{IpamPool: "default-ipam-pool"},
				Name:   swag.String("default"),
				Routes: nil,
			},
		},
		PodName:      "client",
		PodNamespace: "cilium-test",
	}

	ipamHostAddressing := &models.NodeAddressing{
		IPV4: &models.NodeAddressingElement{
			Enabled: true,
			IP:      "10.0.0.1",
		},
		IPV6: &models.NodeAddressingElement{
			Enabled: true,
			IP:      "f00d::1",
		},
	}

	cfgs := constructEndpoints(cniParams, networkResponse)
	assert.Len(t, cfgs, 3)

	ipamResponsePrimary := &models.IPAMResponse{
		Address: &models.AddressPair{
			IPV4:         "192.168.10.10",
			IPV4PoolName: "primary-ipam-pool",
		},
		HostAddressing: ipamHostAddressing,
		IPV4: &models.IPAMAddressResponse{
			IP: "192.168.10.10",
		},
	}
	assert.Equal(t, "eth0", cfgs[0].IfName())
	assert.Equal(t, "primary-ipam-pool", cfgs[0].IPAMPool())
	state, ep, err := cfgs[0].PrepareEndpoint(ipamResponsePrimary)
	assert.NoError(t, err)
	assert.Equal(t, &cmd.CmdState{
		IP4routes: []route.Route{
			{
				Prefix:  *mustParseIPNet("192.168.0.0/24"),
				Nexthop: mustParseIP("192.168.0.1"),
				MTU:     1456,
			},
			{
				Prefix: *mustParseIPNet("192.168.0.1/32"),
			},
			{
				Prefix: defaults.IPv4DefaultRoute,
				Table:  linux_defaults.RouteTableInterfacesOffset + 0,
				MTU:    1456,
			},
		},
		IP4rules: []route.Rule{
			{
				From:     mustParseIPNet("192.168.10.10/32"),
				Table:    linux_defaults.RouteTableInterfacesOffset + 0,
				Protocol: linux_defaults.RTProto,
			},
		},
		HostAddr: ipamHostAddressing,
	}, state)
	assert.Equal(t, &models.EndpointChangeRequest{
		Addressing:             &models.AddressPair{},
		ContainerID:            "container1234",
		ContainerInterfaceName: "eth0",
		DatapathConfiguration:  &models.EndpointDatapathConfiguration{},
		Labels: models.Labels{
			"cni:com.isovalent.v1alpha1.network.attachment=primary",
		},
		K8sPodName:               "client",
		K8sNamespace:             "cilium-test",
		DisableLegacyIdentifiers: false,
		State:                    models.EndpointStateWaitingDashForDashIdentity.Pointer(),
	}, ep)

	ipamResponseSecondary := &models.IPAMResponse{
		Address: &models.AddressPair{
			IPV4:         "172.18.0.10",
			IPV4PoolName: "primay-ipam-pool",
		},
		HostAddressing: ipamHostAddressing,
		IPV4: &models.IPAMAddressResponse{
			IP: "172.18.0.10",
		},
	}
	assert.Equal(t, "cil1", cfgs[1].IfName())
	assert.Equal(t, "secondary-ipam-pool", cfgs[1].IPAMPool())
	state, ep, err = cfgs[1].PrepareEndpoint(ipamResponseSecondary)
	assert.NoError(t, err)
	assert.Equal(t, &cmd.CmdState{
		IP4routes: []route.Route{
			{
				Prefix:  *mustParseIPNet("172.18.0.0/24"),
				Nexthop: mustParseIP("172.18.0.1"),
				MTU:     1456,
			},
			{
				Prefix: *mustParseIPNet("172.18.0.1/32"),
			},
			{
				Prefix: defaults.IPv4DefaultRoute,
				Table:  linux_defaults.RouteTableInterfacesOffset + 1,
				MTU:    1456,
			},
		},
		IP4rules: []route.Rule{
			{
				From:     mustParseIPNet("172.18.0.10/32"),
				Table:    linux_defaults.RouteTableInterfacesOffset + 1,
				Protocol: linux_defaults.RTProto,
			},
		},
	}, state)
	assert.Equal(t, &models.EndpointChangeRequest{
		Addressing:             &models.AddressPair{},
		ContainerID:            "container1234",
		ContainerInterfaceName: "cil1",
		DatapathConfiguration:  &models.EndpointDatapathConfiguration{},
		Labels: models.Labels{
			"cni:com.isovalent.v1alpha1.network.attachment=secondary",
		},
		K8sPodName:               "client",
		K8sNamespace:             "cilium-test",
		DisableLegacyIdentifiers: true,
		State:                    models.EndpointStateWaitingDashForDashIdentity.Pointer(),
	}, ep)

	ipamResponseDefault := &models.IPAMResponse{
		Address: &models.AddressPair{
			IPV4:         "10.10.0.10",
			IPV4PoolName: "default-ipam-pool",
		},
		HostAddressing: ipamHostAddressing,
		IPV4: &models.IPAMAddressResponse{
			IP: "10.10.0.10",
		},
	}
	assert.Equal(t, "cil2", cfgs[2].IfName())
	assert.Equal(t, "default-ipam-pool", cfgs[2].IPAMPool())
	state, ep, err = cfgs[2].PrepareEndpoint(ipamResponseDefault)
	assert.NoError(t, err)
	assert.Equal(t, &cmd.CmdState{
		IP4routes: []route.Route{
			{
				Prefix: defaults.IPv4DefaultRoute,
				Table:  linux_defaults.RouteTableInterfacesOffset + 2,
				MTU:    1456,
			},
		},
		IP4rules: []route.Rule{
			{
				From:     mustParseIPNet("10.10.0.10/32"),
				Table:    linux_defaults.RouteTableInterfacesOffset + 2,
				Protocol: linux_defaults.RTProto,
			},
		},
	}, state)
	assert.Equal(t, &models.EndpointChangeRequest{
		Addressing:               &models.AddressPair{},
		ContainerID:              "container1234",
		ContainerInterfaceName:   "cil2",
		DatapathConfiguration:    &models.EndpointDatapathConfiguration{},
		Labels:                   models.Labels{},
		K8sPodName:               "client",
		K8sNamespace:             "cilium-test",
		DisableLegacyIdentifiers: true,
		State:                    models.EndpointStateWaitingDashForDashIdentity.Pointer(),
	}, ep)
}
