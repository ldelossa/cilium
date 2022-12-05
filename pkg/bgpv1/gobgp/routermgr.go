// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	gobgpb "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	srv6 "github.com/cilium/cilium/pkg/srv6"
)

var (
	// ATTENTION:
	// All logs generated from this package will have the k/v
	// `subsys=bgp-control-plane`.
	//
	// Each log message will additionally contain the k/v
	// 'component=gobgp.{Struct}.{Method}' or 'component=gobgp.{Function}' to
	// provide further granularity on where the log is originating from.
	//
	// Every instantiated BgpServer will log with the k/v
	// `subsys=bgp-control-plane`, `component=gobgp.BgpServerInstance` and
	// `asn={Local ASN}`
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bgp-control-plane")
)

// LocalASNMap maps local ASNs to their associated BgpServers and server
// configuration info.
type LocalASNMap map[int]*ServerWithConfig

// BGPRouterManager implements the pkg.bgpv1.agent.BGPRouterManager interface.
//
// This BGPRouterMananger utilizes the gobgp project to implement a BGP routing
// plane.
//
// Logically, this manager views each CiliumBGPVirtualRouter within a
// CiliumBGPPeeringPolicy as a BGP router instantiated on its host.
//
// BGP routers are grouped and accessed by their local ASNs, thus this backend
// mandates that each CiliumBGPPeeringConfig have a unique local ASN and
// precludes a single host instantiating two routers with the same local ASN.
//
// This manager employs two main data structures to implement its high level
// business logic.
//
// A reconcilerDiff is used to establish which BgpServers must be created,
// and removed from the Mananger along with which servers must have their
// configurations reconciled.
//
// A set of ReconcilerConfigFunc(s), which usages are wrapped by the
// ReconcileBGPConfig function, reconcile individual features of a
// CiliumBGPPeeringConfig.
//
// Together, the high-level flow the manager takes is:
//   - Instantiate a reconcilerDiff to compute which BgpServers to create, remove,
//     and reconcile
//   - Create any BgpServers necessary, run ReconcilerConfigFuncs(s) on each
//   - Run each ReconcilerConfigFunc, by way of ReconcileBGPConfig,
//     on any BgpServers marked for reconcile
//
// BgpServers are abstracted by the ServerWithConfig structure which provides a
// method set for low-level BGP operations.
type BGPRouterManager struct {
	Servers LocalASNMap
}

// NewBGPRouterManager constructs a GoBGP-backed BGPRouterManager.
//
// See NewBGPRouterManager for details.
func NewBGPRouterManager() *BGPRouterManager {
	return &BGPRouterManager{
		Servers: make(LocalASNMap),
	}
}

// ConfigurePeers is a declarative API for configuring the BGP peering topology
// given a desired CiliumBGPPeeringPolicy.
//
// ConfigurePeers will evaluate BGPRouterManager's current state and the desired
// CiliumBGPPeeringPolicy policy then take the necessary actions to apply the
// provided policy. For more details see BGPRouterManager's comments.
//
// ConfigurePeers should return only once a subsequent invocation is safe.
// This method is not thread safe and does not intend to be called concurrently.
func (m *BGPRouterManager) ConfigurePeers(ctx context.Context, policy *v2alpha1api.CiliumBGPPeeringPolicy, cstate *agent.ControlPlaneState) error {
	l := log.WithFields(
		logrus.Fields{
			"component": "gobgp.RouterManager.ConfigurePeers",
		},
	)

	// use a reconcileDiff to compute which BgpServers must be created, removed
	// and reconciled.
	rd := newReconcileDiff(cstate)

	if policy == nil {
		return m.withdrawAll(ctx, rd)
	}

	rd.diff(m.Servers, policy)

	if rd.empty() {
		l.Debug("GoBGP peering topology up-to-date with CiliumBGPPeeringPolicy for this node.")
		return nil
	}
	l.WithField("diff", rd.String()).Debug("Reconciling new CiliumBGPPeeringPolicy")

	if len(rd.register) > 0 {
		if err := m.register(ctx, rd); err != nil {
			return fmt.Errorf("encountered error adding new BGP Servers: %v", err)
		}
	}
	if len(rd.withdraw) > 0 {
		if err := m.withdraw(ctx, rd); err != nil {
			return fmt.Errorf("encountered error removing existing BGP Servers: %v", err)
		}
	}
	if len(rd.reconcile) > 0 {
		if err := m.reconcile(ctx, rd); err != nil {
			return fmt.Errorf("encountered error reconciling existing BGP Servers: %v", err)
		}
	}
	return nil
}

// register instantiates and configures BgpServer(s) as instructed by the provided
// work diff.
func (m *BGPRouterManager) register(ctx context.Context, rd *reconcileDiff) error {
	l := log.WithFields(
		logrus.Fields{
			"component": "gobgp.RouterManager.add",
		},
	)
	for _, asn := range rd.register {
		var config *v2alpha1api.CiliumBGPVirtualRouter
		var ok bool
		if config, ok = rd.seen[asn]; !ok {
			l.Errorf("Work diff (add) contains unseen ASN %v, skipping", asn)
			continue
		}
		if err := m.registerBGPServer(ctx, config, rd.state); err != nil {
			// we'll just log the error and attempt to register the next BgpServer.
			l.WithError(err).Errorf("Error while registering new BGP server for local ASN %v.", config.LocalASN)
		}
	}
	return nil
}

// registerBGPServer encapsulates the logic for instantiating a gobgp
// BgpServer, configuring it based on a CiliumBGPVirtualRouter, and
// registering it with the Manager.
//
// If this registration process fails the server will be stopped (if it was started)
// and deleted from our manager (if it was added).
func (m *BGPRouterManager) registerBGPServer(ctx context.Context, c *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	l := log.WithFields(
		logrus.Fields{
			"component": "gobgp.RouterManager.registerBGPServer",
		},
	)

	l.Infof("Registering GoBGP servers for policy with local ASN %v", c.LocalASN)

	// ATTENTION: this defer handles cleaning up of a server if an error in
	// registration occurs. for this to work the below err variable must be
	// overwritten for the lengh of this method.
	var err error
	var s *ServerWithConfig
	defer func() {
		if err != nil {
			if s != nil {
				s.Server.Stop()
			}
			delete(m.Servers, c.LocalASN) // optimistic delete
		}
	}()

	// resolve local port from kubernetes annotations
	var localPort int32
	localPort = -1
	if attrs, ok := cstate.Annotations[c.LocalASN]; ok {
		if attrs.LocalPort != 0 {
			localPort = int32(attrs.LocalPort)
		}
	}

	// resolve router ID, if we have an annotation and it can be parsed into
	// a valid ipv4 address use this,
	//
	// if not determine if Cilium is configured with an IPv4 address, if so use
	// this.
	//
	// if neither, return an error, we cannot assign an router ID.
	var routerID string
	_, ok := cstate.Annotations[c.LocalASN]
	switch {
	case ok && !net.ParseIP(cstate.Annotations[c.LocalASN].RouterID).IsUnspecified():
		routerID = cstate.Annotations[c.LocalASN].RouterID
	case !cstate.IPv4.IsUnspecified():
		routerID = cstate.IPv4.String()
	default:
		return fmt.Errorf("router id not specified by annotation and no IPv4 address assigned by cilium, cannot resolve router id for virtual router with local ASN %v", c.LocalASN)
	}

	startReq := &gobgp.StartBgpRequest{
		Global: &gobgp.Global{
			Asn:        uint32(c.LocalASN),
			RouterId:   routerID,
			ListenPort: localPort,
			RouteSelectionOptions: &gobgp.RouteSelectionOptionsConfig{
				AdvertiseInactiveRoutes: true,
			},
		},
	}

	if s, err = NewServerWithConfig(ctx, startReq, cstate); err != nil {
		return fmt.Errorf("failed to start BGP server for config with local ASN %v: %w", c.LocalASN, err)
	}

	if err = ReconcileBGPConfig(ctx, m, s, c, cstate); err != nil {
		return fmt.Errorf("failed initial reconciliation for peer config with local ASN %v: %w", c.LocalASN, err)
	}

	// register with manager
	m.Servers[c.LocalASN] = s
	l.Infof("Successfully registered GoBGP servers for policy with local ASN %v", c.LocalASN)

	return err
}

// withdraw disconnects and removes BgpServer(s) as instructed by the provided
// work diff.
func (m *BGPRouterManager) withdraw(ctx context.Context, rd *reconcileDiff) error {
	l := log.WithFields(
		logrus.Fields{
			"component": "gobgp.RouterManager.remove",
		},
	)
	for _, asn := range rd.withdraw {
		var (
			s  *ServerWithConfig
			ok bool
		)
		if s, ok = m.Servers[asn]; !ok {
			l.Warnf("Server with local ASN %v marked for deletion but does not exist", asn)
			continue
		}
		s.Server.Stop()
		delete(m.Servers, asn)
		l.Infof("Removed BGP server with local ASN %v", asn)
	}
	return nil
}

// withdrawAll will disconnect and remove all currently registered BgpServer(s).
//
// `rd` must be a newly created reconcileDiff which has not had its `Diff` method
// called.
func (m *BGPRouterManager) withdrawAll(ctx context.Context, rd *reconcileDiff) error {
	if len(m.Servers) == 0 {
		return nil
	}
	for asn := range m.Servers {
		rd.withdraw = append(rd.withdraw, asn)
	}
	return m.withdraw(ctx, rd)
}

// reconcile evaluates existing BgpServer(s), making changes if necessary, as
// instructed by the provided reoncileDiff.
func (m *BGPRouterManager) reconcile(ctx context.Context, rd *reconcileDiff) error {
	l := log.WithFields(
		logrus.Fields{
			"component": "gobgp.RouterManager.reconcile",
		},
	)
	for _, asn := range rd.reconcile {
		var (
			sc   = m.Servers[asn]
			newc = rd.seen[asn]
		)
		if sc == nil {
			l.Errorf("Virtual router with local ASN %v marked for reconciliation but missing from Manager", newc.LocalASN) // really shouldn't happen
			continue
		}
		if newc == nil {
			l.Errorf("Virtual router with local ASN %v marked for reconciliation but missing from incoming configurations", sc.Config.LocalASN) // also really shouldn't happen
			continue
		}

		if err := ReconcileBGPConfig(ctx, m, sc, newc, rd.state); err != nil {
			l.WithError(err).Errorf("Encountered error reconciling virtual router with local ASN %v, shutting down this server", newc.LocalASN)
			sc.Server.Stop()
			delete(m.Servers, asn)
		}
	}
	return nil
}

func MapVPNv4ToEgressPolicy(ctx context.Context, vpnv4 *gobgp.Path, vrfs []*srv6.VRF) ([]*srv6.EgressPolicy, error) {
	l := log.WithFields(
		logrus.Fields{
			"component": "gobgp.RouterManager.MapVPNv4ToEgressPolicy",
		},
	)

	// require extended communities for route target.
	var extCommunities *gobgpb.PathAttributeExtendedCommunities
	// require MP BGP Reach NLRIs to mape prefixes to destination CIDRs
	var mpReach *gobgpb.PathAttributeMpReachNLRI
	// require BGP prefix-sid attribute to extract destination CIDR
	var prefixSID *gobgpb.PathAttributePrefixSID
	// extracted prefixes from MP BGP VPNv4 NLRI
	var prefixes []*net.IPNet
	// extracted route target from BGP extended community.
	var RT string
	// extracted SRv6 SID from BGP Prefix SID attribute.
	var destinationSID [16]byte

	attrs, err := apiutil.UnmarshalPathAttributes(vpnv4.Pattrs)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal path attributes: %w", err)
	}

	for _, attr := range attrs {
		switch v := attr.(type) {
		case *gobgpb.PathAttributeExtendedCommunities:
			extCommunities = v
		case *gobgpb.PathAttributeMpReachNLRI:
			mpReach = v
		case *gobgpb.PathAttributePrefixSID:
			prefixSID = v
		}
	}

	// if we do not have our required path attributes we cannot map this route.
	// this is not an error.
	if extCommunities == nil {
		l.Debug("Did not find extended communities")
		return nil, nil
	}
	if mpReach == nil {
		l.Debug("Did not find MB NLRIs")
		return nil, nil
	}
	if prefixSID == nil {
		l.Debug("Did not find BGP Prefix SID attribute")
		return nil, nil
	}

	l.Debug("Looking for route target extended community")
	for _, val := range extCommunities.Value {
		switch v := val.(type) {
		case *gobgpb.FourOctetAsSpecificExtended:
			if v.SubType == gobgpb.EC_SUBTYPE_ROUTE_TARGET {
				l.WithField("routeTarget", RT).Debug("Discovered route target in Two-Octect AS Specific Ext Community")
				RT = fmt.Sprintf("%d:%d", v.AS, v.LocalAdmin)
			}
		case *gobgpb.TwoOctetAsSpecificExtended:
			if v.SubType == gobgpb.EC_SUBTYPE_ROUTE_TARGET {
				RT = fmt.Sprintf("%d:%d", v.AS, v.LocalAdmin)
				l.WithField("routeTarget", RT).Debug("Discovered route target in Two-Octect AS Specific Ext Community")
			}
		}
	}
	// we did not find a route target.
	if RT == "" {
		l.Debug("Did not find a route target")
		return nil, nil
	}

	// extract our destination CIDRs from MP BGP NLRIs.
	// these will be VPNv4 encoded IPv4 prefixes.
	if (mpReach.SAFI != gobgpb.SAFI_MPLS_VPN) || (mpReach.AFI != gobgpb.AFI_IP) {
		// this really shouldn't happen since we do a list for paths of this
		// S/AFI type, but may as well be defensive.
		l.Debug("MB BGP NLRI was not correct S/AFI")
		return nil, nil
	}

	var labels []uint32
	for _, prefix := range mpReach.Value {
		switch v := prefix.(type) {
		case *gobgpb.LabeledVPNIPAddrPrefix:
			labels = v.Labels.Labels
			mask := net.CIDRMask(int(v.IPPrefixLen()), 32)
			prefixes = append(prefixes, &net.IPNet{
				IP:   v.Prefix,
				Mask: mask,
			})
		}
	}
	if len(prefixes) == 0 {
		l.Debug("No prefixes provided in VPNv4 path")
		return nil, nil
	}

	// first extract SRv6 SID Information Sub-TLV
	// (RFC draft-ietf-bess-srv6-services 3.1) to obtain destination SID.
	//
	// per RFC:
	// When multiple SRv6 SID Information Sub-TLVs are present, the ingress
	// PE SHOULD use the SRv6 SID from the first instance of the Sub-TLV.
	// An implementation MAY provide a local policy to override this
	// selection.
	//
	// we will only utilize the first SID Info Sub-TLV
	unpackL3Serv := func(l3serv *gobgpb.SRv6L3ServiceAttribute) *gobgpb.SRv6InformationSubTLV {
		for _, subtlv := range l3serv.SubTLVs {
			switch v := subtlv.(type) {
			case *gobgpb.SRv6InformationSubTLV:
				return v
			}
		}
		return nil
	}

	// pull out the first occurrence as well, there doesn't seem to be good reason
	// to parse out multiple.
	unpackInfoSubTLV := func(subtlv *gobgpb.SRv6InformationSubTLV) *gobgpb.SRv6SIDStructureSubSubTLV {
		var subStructTLV *gobgpb.SRv6SIDStructureSubSubTLV
		for _, subsubtlv := range subtlv.SubSubTLVs {
			switch v := subsubtlv.(type) {
			case *gobgpb.SRv6SIDStructureSubSubTLV:
				subStructTLV = v
			}
		}
		return subStructTLV
	}

	for _, tlv := range prefixSID.TLVs {
		switch v := tlv.(type) {
		case *gobgpb.SRv6L3ServiceAttribute:
			infoSubTLV := unpackL3Serv(v)
			if infoSubTLV == nil {
				continue
			}
			subStructTLV := unpackInfoSubTLV(infoSubTLV)
			if subStructTLV == nil {
				continue
			}
			// per RFC (draft-ietf-bess-srv6-services) if Transposition length
			// is not zero the SID was transposed with an MPLS label.
			if subStructTLV.TranspositionLength != 0 {
				l.Debug("Must transpose MPLS label to obtain SID.")

				if len(labels) == 0 {
					return nil, fmt.Errorf("VPNv4 path expects transposition of SID but no MPLS labels discovered")
				}

				transposed, err := TransposeSID(labels[0], infoSubTLV, subStructTLV)
				if err != nil {
					return nil, fmt.Errorf("failed to transpose SID: %w", err)
				}
				for i, b := range transposed {
					destinationSID[i] = b
				}
			} else {
				for i, b := range infoSubTLV.SID {
					destinationSID[i] = b
				}
			}
		}
	}

	// map into EgressPolicies
	policies := []*srv6.EgressPolicy{}
	for _, vrf := range vrfs {
		if vrf == nil {
			continue
		}
		if vrf.ImportRouteTarget == RT {
			l.Debugf("Matched vrf's route target %v with discovered route target %v", vrf.ImportRouteTarget, RT)
			policy := &srv6.EgressPolicy{
				VRFID:    vrf.VRFID,
				DstCIDRs: prefixes,
				SID:      destinationSID,
			}
			policies = append(policies, policy)
			l.WithField("policy", policy).Debug("Mapped VPNv4 route to policy.")
		}
	}

	return policies, nil
}

// MapSRv6EgressPolicy will map any discovered VPNv4 routes which match passed in
// VRF's route reflectors into srv6.EgressPolicy(s) and return these to the caller.
func (m *BGPRouterManager) MapSRv6EgressPolicy(ctx context.Context, vrfs []*srv6.VRF) ([]*srv6.EgressPolicy, error) {
	l := log.WithFields(
		logrus.Fields{
			"component": "gobgp.RouterManager.MapSRv6EgressPolicy",
		},
	)
	l.Info("Mapping SRv6 VRFs to SRv6 egress policies.")

	var (
		VPNv4Paths []*gobgp.Path
		policies   []*srv6.EgressPolicy
	)

	for localASN, bgp := range m.Servers {
		if bgp.Config.MapSRv6VRFs {
			l.Infof("Evaluating virtual router with local ASN %d for SRv6 egress policy mapping", bgp.Config.LocalASN)

			lpr := &gobgp.ListPathRequest{
				TableType: gobgp.TableType_GLOBAL,
				Family:    GoBGPVPNv4Family,
			}

			err := bgp.Server.ListPath(ctx, lpr, func(d *gobgp.Destination) {
				for _, p := range d.Paths {
					if p.Best {
						VPNv4Paths = append(VPNv4Paths, d.Paths...)
					}
				}
			})
			if err != nil {
				return nil, fmt.Errorf("failed to list VPNv4 paths for virtual router with local ASN %d: %w", localASN, err)
			}
		}
	}
	l.WithField("count", len(VPNv4Paths)).Info("Discovered advertised VPNv4 routes.")

	for _, p := range VPNv4Paths {
		out, err := MapVPNv4ToEgressPolicy(ctx, p, vrfs)
		if err != nil {
			return nil, fmt.Errorf("failed to map VPNv4 paths to egress policies: %w", err)
		}
		policies = append(policies, out...)
	}
	l.WithField("count", len(policies)).Info("Mapped VPNv4 paths to egress policies")
	return policies, nil
}
