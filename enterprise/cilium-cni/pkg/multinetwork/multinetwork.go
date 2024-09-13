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
	"fmt"
	"net"

	"github.com/go-openapi/swag"

	"github.com/cilium/cilium/api/v1/models"
	enterpriseModels "github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/enterprise/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/plugins/cilium-cni/cmd"
)

const attachmentLabelName = "com.isovalent.v1alpha1.network.attachment"

type endpointConfigurator struct{}

// NewEndpointConfigurator returns a multi-network aware endpoint configurator
// implementing the cmd.EndpointConfigurator interface.
func NewEndpointConfigurator() *endpointConfigurator {
	return &endpointConfigurator{}
}

// GetConfigurations determines how many endpoints need to be created for this
// CNI ADD invocation. For every endpoint, we determine the multi-network metadata
// via the `GET /networks/attachment` API call. If the multi-network is disabled,
// we fall back on the default implementation used by the OSS CNI plugin.
func (e *endpointConfigurator) GetConfigurations(p cmd.ConfigurationParams) ([]cmd.EndpointConfiguration, error) {
	ceeClient, err := client.NewDefaultClient()
	if err != nil {
		return nil, fmt.Errorf("unable to create enterprise API client: %w", err)
	}

	// check if multi-network is enabled
	ec, err := ceeClient.EnterpriseConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to get enterprise configuration: %w", err)
	}

	if !ec.MultiNetwork {
		// fall back on OSS implementation if multi-network is not enabled
		ossImpl := cmd.DefaultConfigurator{}
		return ossImpl.GetConfigurations(p)
	}

	// fetch network attachments
	networks, err := ceeClient.NetworkAttachments(string(p.CniArgs.K8S_POD_NAMESPACE), string(p.CniArgs.K8S_POD_NAME))
	if err != nil {
		return nil, fmt.Errorf("unable to determine network attachments: %w", err)
	}

	eps := constructEndpoints(p, networks)

	return eps, nil
}

// constructEndpoints takes the result from the `GET /network/attachment/`
// API call and constructs a list of endpoint configurations based on it.
func constructEndpoints(p cmd.ConfigurationParams, networks *enterpriseModels.NetworkAttachmentList) []cmd.EndpointConfiguration {
	// construct one endpointConfiguration for each network attachment
	multipleInterfaces := len(networks.Attachments) > 1
	eps := make([]cmd.EndpointConfiguration, 0, len(networks.Attachments))
	for i, attachment := range networks.Attachments {
		networkName := swag.StringValue(attachment.Name)
		isDefault := networkName == "default"
		isPrimary := i == 0

		ifName := p.Args.IfName
		if !isPrimary {
			ifName = fmt.Sprintf("cil%d", i)
		}

		eps = append(eps, &endpointConfiguration{
			isDefault:            isDefault,
			isPrimary:            isPrimary,
			networkName:          networkName,
			installNetworkRoutes: multipleInterfaces,
			ifName:               ifName,
			ifNumber:             i,
			attachment:           attachment,
			params:               p,
		})
	}
	return eps
}

// endpointConfiguration contains all the relevant info
type endpointConfiguration struct {
	// isDefault is set if this endpoint is attached to the "default" network
	isDefault bool
	// isDefault is set if this endpoint is the primary (i.e. first) interface
	isPrimary bool
	// installNetworkRoutes is set to true if this endpoint is part of a
	// multi-networked pod and thus we want to install PodNetwork routes
	installNetworkRoutes bool

	// ifNumber is a numeric index for the network interface in the container
	// namespace. This is based on the order of the network attachments returned
	// by `GET /network/attachments`. This is _not_ to be confused with the
	// Linux ifindex.
	ifNumber int
	// ifName is the name of the container interface of this endpoint
	ifName string
	// networkName is the name of the network this endpoint is attached to
	networkName string
	// attachment contains the metadata of the network this endpoint is attached to
	attachment *enterpriseModels.NetworkAttachmentElement

	params cmd.ConfigurationParams
}

// IfName specifies the container interface name to be used for this endpoint
func (e *endpointConfiguration) IfName() string {
	return e.ifName
}

// IPAMPool specifies which IPAM pool the endpoint's IP should be allocated from
func (e *endpointConfiguration) IPAMPool() string {
	if e.attachment.Ipam == nil {
		return ""
	}
	return e.attachment.Ipam.IpamPool
}

func ipv6IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV6 == "" {
		return false
	}

	if ipam.HostAddressing != nil && ipam.HostAddressing.IPV6 != nil {
		return ipam.HostAddressing.IPV6.Enabled
	}

	return true
}

func ipv4IsEnabled(ipam *models.IPAMResponse) bool {
	if ipam == nil || ipam.Address.IPV4 == "" {
		return false
	}

	if ipam.HostAddressing != nil && ipam.HostAddressing.IPV4 != nil {
		return ipam.HostAddressing.IPV4.Enabled
	}

	return true
}

// installIsovalentPodNetworkRoutes takes the PodNetwork routes from the CRD and
// writes them into the CmdState 'state'. That 'state' will be used by the caller
// of PrepareEndpoint to install those routes in the container network namespace.
func installIsovalentPodNetworkRoutes(state *cmd.CmdState, routes []*enterpriseModels.NetworkAttachmentRoute, ipam *models.IPAMResponse, routeMTU int) error {
	doIPv4 := ipv4IsEnabled(ipam)
	doIPv6 := ipv6IsEnabled(ipam)

	for _, r := range routes {
		dstIP, dstPrefix, err := net.ParseCIDR(r.Destination)
		if err != nil {
			return fmt.Errorf("invalid route destination: %w", err)
		}

		var gwIP net.IP
		if r.Gateway != "" {
			gwIP = net.ParseIP(r.Gateway)
			if gwIP == nil {
				return fmt.Errorf("invalid route gateway %q", r.Gateway)
			}
		}

		isIPv6Route := dstIP.To4() == nil
		if (isIPv6Route && !doIPv6) || (!isIPv6Route && !doIPv4) {
			continue
		}

		var resultRoutes []route.Route
		resultRoutes = append(resultRoutes, route.Route{
			Prefix:  *dstPrefix,
			Nexthop: &gwIP,
			MTU:     routeMTU,
		})

		if gwIP != nil {
			resultRoutes = append(resultRoutes, route.Route{
				Prefix: *iputil.IPToPrefix(gwIP),
			})
		}

		if isIPv6Route {
			state.IP6routes = append(state.IP6routes, resultRoutes...)
		} else {
			state.IP4routes = append(state.IP4routes, resultRoutes...)
		}
	}
	return nil
}

// installMultiNetworkSourceRoutes generates the IP rules and routes needed
// to support cross-network traffic in a multi-networked pod.
// If there is cross-network traffic, the network routes can cause the
// reply packet to leave on a different interface than the one it was
// received on. This causes Cilium to drop the reply packet because the
// packet on the egress interface does not match the egress interface's
// source IP (Cilium performs endpoint source IP verification in the
// datapath).
//
// To solve this, we install a source IP based IP rule that redirects
// packet with a pre-determined source IP over the interface where that IP
// is attached to.
func installMultiNetworkSourceRoutes(state *cmd.CmdState, ifNumber int, ipam *models.IPAMResponse, routeMTU int) {
	// This shouldn't conflict with the main routing table IDs (253-255)
	// because we don't expect more than 243 (253-10) networks being used at the
	// same time.
	tableID := linux_defaults.RouteTableInterfacesOffset + ifNumber

	if ipv4IsEnabled(ipam) {
		state.IP4routes = append(state.IP4routes, route.Route{
			Prefix: defaults.IPv4DefaultRoute,
			MTU:    routeMTU,
			Table:  tableID,
		})

		state.IP4rules = append(state.IP4rules, route.Rule{
			From:     iputil.IPToPrefix(net.ParseIP(ipam.Address.IPV4)),
			Table:    tableID,
			Protocol: linux_defaults.RTProto,
		})
	}

	if ipv6IsEnabled(ipam) {
		state.IP6routes = append(state.IP6routes, route.Route{
			Prefix: defaults.IPv6DefaultRoute,
			MTU:    routeMTU,
			Table:  tableID,
		})

		state.IP6rules = append(state.IP6rules, route.Rule{
			From:     iputil.IPToPrefix(net.ParseIP(ipam.Address.IPV6)),
			Table:    tableID,
			Protocol: linux_defaults.RTProto,
		})
	}
}

// PrepareEndpoint returns the interface configuration 'cmd' of the container
// namespace as well as the template for the endpoint creation request 'ep'.
// The returned endpoint contains one additional label with the network name
// if this endpoint is attached to a non-default network. This allows policies
// to select endpoints based on the attached network.
// The returned CmdState state contains the rules and routes needed to steer
// traffic over the correct interface for multi-networked pods.
func (e *endpointConfiguration) PrepareEndpoint(ipam *models.IPAMResponse) (state *cmd.CmdState, ep *models.EndpointChangeRequest, err error) {
	var lbls labels.Labels
	if !e.isDefault {
		lbls = labels.Labels{
			attachmentLabelName: labels.NewLabel(attachmentLabelName, e.networkName, labels.LabelSourceCNI),
		}
		e.params.Log.WithField("label", lbls.String()).Debug("adding label for non-default endpoint")
	}

	ep = &models.EndpointChangeRequest{
		ContainerID:              e.params.Args.ContainerID,
		Labels:                   lbls.GetModel(),
		State:                    models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		Addressing:               &models.AddressPair{},
		K8sPodName:               string(e.params.CniArgs.K8S_POD_NAME),
		K8sNamespace:             string(e.params.CniArgs.K8S_POD_NAMESPACE),
		ContainerInterfaceName:   e.ifName,
		DatapathConfiguration:    &models.EndpointDatapathConfiguration{},
		DisableLegacyIdentifiers: !e.isPrimary,
	}

	if e.params.Conf.IpamMode == ipamOption.IPAMDelegatedPlugin {
		// Prevent cilium agent from trying to release the IP when the endpoint is deleted.
		ep.DatapathConfiguration.ExternalIpam = true
	}

	state = &cmd.CmdState{}
	if e.isPrimary {
		// This will cause a default route to be installed by the caller
		state.HostAddr = ipam.HostAddressing
	}

	if e.installNetworkRoutes {
		routeMTU := int(e.params.Conf.RouteMTU)
		err = installIsovalentPodNetworkRoutes(state, e.attachment.Routes, ipam, routeMTU)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create IsovalentPodNetwork routes: %w", err)
		}

		installMultiNetworkSourceRoutes(state, e.ifNumber, ipam, routeMTU)
	}

	return state, ep, nil
}
