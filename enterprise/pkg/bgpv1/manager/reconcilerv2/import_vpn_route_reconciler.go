// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/sirupsen/logrus"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	srv6 "github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
)

type ImportedVPNRouteReconcilerOut struct {
	cell.Out

	Reconciler reconcilerv2.StateReconciler `group:"bgp-state-reconciler-v2"`
}

type ImportedVPNRouteReconcilerIn struct {
	cell.In

	Logger       logrus.FieldLogger
	Clientset    client.Clientset
	Config       config.Config
	DaemonConfig *option.DaemonConfig
	Upgrader     paramUpgrader
	SRv6Manager  *srv6.Manager
}

type ImportedVPNRouteReconciler struct {
	Logger      logrus.FieldLogger
	Clientset   client.Clientset
	Upgrader    paramUpgrader
	SRv6Manager SRv6Manager
}

func NewImportedVPNRouteReconciler(params ImportedVPNRouteReconcilerIn) ImportedVPNRouteReconcilerOut {
	if !params.Config.Enabled || !params.DaemonConfig.EnableSRv6 {
		return ImportedVPNRouteReconcilerOut{}
	}

	return ImportedVPNRouteReconcilerOut{
		Reconciler: &ImportedVPNRouteReconciler{
			Logger:      params.Logger.WithField(types.ReconcilerLogField, "import-vpn-route"),
			Clientset:   params.Clientset,
			Upgrader:    params.Upgrader,
			SRv6Manager: params.SRv6Manager,
		},
	}
}

func (r *ImportedVPNRouteReconciler) Name() string {
	return "ImportedVPNRouteReconciler"
}

func (r *ImportedVPNRouteReconciler) Priority() int {
	return 20
}

func (r *ImportedVPNRouteReconciler) Init(_ *instance.BGPInstance) error {
	return nil
}

func (r *ImportedVPNRouteReconciler) Cleanup(_ *instance.BGPInstance) {}

func (r *ImportedVPNRouteReconciler) Reconcile(ctx context.Context, p reconcilerv2.StateReconcileParams) error {
	iParams, err := r.Upgrader.upgradeState(p)
	if err != nil {
		if errors.Is(err, NotInitializedErr) {
			r.Logger.Debug("Initialization is not done, skipping imported VPN route reconciliation")
			return nil
		}
		if errors.Is(err, UpdateConfigNotSetErr) {
			r.Logger.Debug("Instance config not yet set, skipping imported VPN route reconciliation")
			return nil
		}
		return err
	}

	if iParams.DeletedInstance != "" {
		// TODO: we currently do not handle instance deletion as egress policies are not keyed based on
		// instance name. We should consider adding a key based on instance name to egress policies.
		// Eventually we need to rework SRv6 responder, when we should consider fixing this case.
		r.Logger.Debug("BGP instance delete event, skipping imported VPN route reconciliation")
		return nil
	}

	if iParams.DesiredConfig.SRv6Responder == nil || !*iParams.DesiredConfig.SRv6Responder {
		// If node is not SRv6 responder, we don't need to reconcile imported VPN routes
		r.Logger.Debug("Node is not SRv6 responder, skipping imported VPN route reconciliation")
		return nil
	}

	var (
		l = r.Logger.WithFields(
			logrus.Fields{
				types.InstanceLogField: iParams.DesiredConfig.Name,
			},
		)
		toCreate []*srv6.EgressPolicy
		toRemove []*srv6.EgressPolicy
	)

	curPolicies := r.SRv6Manager.GetEgressPolicies()
	r.Logger.WithField("count", len(curPolicies)).Debug("Discovered current egress policies")

	newPolicies, err := r.mapSRv6PathsToEgressPolicy(ctx, l, iParams.UpdatedInstance.Router, iParams.DesiredConfig.VRFs)
	if err != nil {
		return fmt.Errorf("failed to map VRFs into SRv6 egress policies: %w", err)
	}

	// an nset member which book keeps which universe it exists in.
	type member struct {
		// present in new policies universe
		a bool
		// present in current policies universe
		b bool
		p *srv6.EgressPolicy
	}

	// set of unique policies
	pset := map[string]*member{}

	// evaluate new policies
	for i, p := range newPolicies {

		var (
			h  *member
			ok bool
		)

		key, err := keyifySRv6Policy(p)
		if err != nil {
			return fmt.Errorf("%s %w", "failed to create key from EgressPolicy", err)
		}

		if h, ok = pset[key]; !ok {
			pset[key] = &member{
				a: true,
				p: newPolicies[i],
			}
			continue
		}
		h.a = true
	}
	// evaluate current policies
	for i, p := range curPolicies {
		var (
			h  *member
			ok bool
		)

		key, err := keyifySRv6Policy(p)
		if err != nil {
			return fmt.Errorf("%s %w", "failed to create key from EgressPolicy", err)
		}

		if h, ok = pset[key]; !ok {
			pset[key] = &member{
				b: true,
				p: curPolicies[i],
			}
			continue
		}
		h.b = true
	}

	for _, m := range pset {
		// present in new policies but not in current, create
		if m.a && !m.b {
			toCreate = append(toCreate, m.p)
		}
		// present in current policies but not new, remove.
		if m.b && !m.a {
			toRemove = append(toRemove, m.p)
		}
	}
	l.WithField("count", len(toCreate)).Debug("Number of SRv6 egress policies to create.")
	l.WithField("count", len(toRemove)).Debug("Number of SRv6 egress policies to remove.")

	clientSet := r.Clientset.IsovalentV1alpha1().IsovalentSRv6EgressPolicies()

	mkName := func(p *srv6.EgressPolicy) (string, error) {
		const prefix = "bgp-control-plane"

		key, err := keyifySRv6Policy(p)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("%s-%s", prefix, key), nil
	}

	var name string

	for _, p := range toCreate {
		destCIDRs := []v1alpha1.CIDR{}
		for _, c := range p.DstCIDRs {
			destCIDRs = append(destCIDRs, v1alpha1.CIDR(c.String()))
		}

		name, err = mkName(p)
		if err != nil {
			return fmt.Errorf("failed to create EgressPolicy name: %w", err)
		}

		egressPol := &v1alpha1.IsovalentSRv6EgressPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			TypeMeta: metav1.TypeMeta{
				APIVersion: "isovalent.com/v1alpha1",
				Kind:       "IsovalentSRv6EgressPolicy",
			},
			Spec: v1alpha1.IsovalentSRv6EgressPolicySpec{
				VRFID:            p.VRFID,
				DestinationCIDRs: destCIDRs,
				DestinationSID:   p.SID.IP().String(),
			},
		}
		l.WithField("policy", egressPol).Debug("Writing egress policy to Kubernetes")
		res, err := clientSet.Create(ctx, egressPol, metav1.CreateOptions{})
		if err != nil && !k8sErrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to write egress policy to Kubernetes: %w", err)
		}
		l.WithField("policy", res).Debug("Resulting egress policy")
	}

	for _, p := range toRemove {
		name, err = mkName(p)
		if err != nil {
			return fmt.Errorf("failed to create EgressPolicy name: %w", err)
		}

		l.WithField("policy", p).Debug("Removing egress policy from Kubernetes")
		err := clientSet.Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil && !k8sErrors.IsNotFound(err) {
			return fmt.Errorf("failed to remove egress policy: %w", err)
		}
	}

	return nil
}

func (r *ImportedVPNRouteReconciler) mapSRv6PathsToEgressPolicy(ctx context.Context, l logrus.FieldLogger, bgpRouter types.Router, vrfs []v1alpha1.IsovalentBGPNodeVRF) ([]*srv6.EgressPolicy, error) {
	l.Debug("Mapping SRv6 VRFs to SRv6 egress policies.")

	var policies []*srv6.EgressPolicy

	resp, err := bgpRouter.GetRoutes(ctx, &types.GetRoutesRequest{
		TableType: types.TableTypeLocRIB,
		Family: types.Family{
			Afi:  types.AfiIPv4,
			Safi: types.SafiMplsVpn,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list VPNv4 paths: %w", err)
	}

	l.WithField("count", len(resp.Routes)).Debug("Discovered learned VPNv4 routes.")

	for _, route := range resp.Routes {
		for _, p := range route.Paths {
			if p.Best {
				out, err := r.mapSRv6PathToEgressPolicy(l, p.PathAttributes, vrfs)
				if err != nil {
					return nil, fmt.Errorf("failed to map VPNv4 paths to egress policies: %w", err)
				}
				policies = append(policies, out...)
			}
		}
	}

	l.WithField("count", len(policies)).Debug("Mapped VPNv4 paths to egress policies")

	return policies, nil
}

func (r *ImportedVPNRouteReconciler) mapSRv6PathToEgressPolicy(l logrus.FieldLogger, attrs []bgp.PathAttributeInterface, bgpVRFs []v1alpha1.IsovalentBGPNodeVRF) ([]*srv6.EgressPolicy, error) {
	var (
		// require extended communities for route target.
		extCommunities *bgp.PathAttributeExtendedCommunities
		// require MP BGP Reach NLRIs to mape prefixes to destination CIDRs
		mpReach *bgp.PathAttributeMpReachNLRI
		// require BGP prefix-sid attribute to extract destination CIDR
		prefixSID *bgp.PathAttributePrefixSID
		// extracted prefixes from MP BGP VPNv4 NLRI
		prefixes []netip.Prefix
		// extracted route target from BGP extended community.
		RT string
		// extracted SRv6 SID from BGP Prefix SID attribute.
		destinationSID [16]byte
	)

	for _, attr := range attrs {
		switch v := attr.(type) {
		case *bgp.PathAttributeExtendedCommunities:
			extCommunities = v
		case *bgp.PathAttributeMpReachNLRI:
			mpReach = v
		case *bgp.PathAttributePrefixSID:
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
		case *bgp.FourOctetAsSpecificExtended:
			if v.SubType == bgp.EC_SUBTYPE_ROUTE_TARGET {
				l.WithField("routeTarget", RT).Debug("Discovered route target in Two-Octect AS Specific Ext Community")
				RT = fmt.Sprintf("%d:%d", v.AS, v.LocalAdmin)
			}
		case *bgp.TwoOctetAsSpecificExtended:
			if v.SubType == bgp.EC_SUBTYPE_ROUTE_TARGET {
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
	if (mpReach.SAFI != bgp.SAFI_MPLS_VPN) || (mpReach.AFI != bgp.AFI_IP) {
		// this really shouldn't happen since we do a list for paths of this
		// S/AFI type, but may as well be defensive.
		l.Debug("MB BGP NLRI was not correct S/AFI")
		return nil, nil
	}

	var labels []uint32
	for _, prefix := range mpReach.Value {
		switch v := prefix.(type) {
		case *bgp.LabeledVPNIPAddrPrefix:
			labels = v.Labels.Labels
			addr, ok := netip.AddrFromSlice(v.Prefix)
			if ok {
				prefixes = append(prefixes, netip.PrefixFrom(addr, int(v.IPPrefixLen())))
			}
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
	unpackL3Serv := func(l3serv *bgp.SRv6L3ServiceAttribute) *bgp.SRv6InformationSubTLV {
		for _, subtlv := range l3serv.SubTLVs {
			switch v := subtlv.(type) {
			case *bgp.SRv6InformationSubTLV:
				return v
			}
		}
		return nil
	}

	// pull out the first occurrence as well, there doesn't seem to be good reason
	// to parse out multiple.
	unpackInfoSubTLV := func(subtlv *bgp.SRv6InformationSubTLV) *bgp.SRv6SIDStructureSubSubTLV {
		var subStructTLV *bgp.SRv6SIDStructureSubSubTLV
		for _, subsubtlv := range subtlv.SubSubTLVs {
			switch v := subsubtlv.(type) {
			case *bgp.SRv6SIDStructureSubSubTLV:
				subStructTLV = v
			}
		}
		return subStructTLV
	}

	for _, tlv := range prefixSID.TLVs {
		switch v := tlv.(type) {
		case *bgp.SRv6L3ServiceAttribute:
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

				transposed, err := transposeSID(l, labels[0], infoSubTLV, subStructTLV)
				if err != nil {
					return nil, fmt.Errorf("failed to transpose SID: %w", err)
				}
				copy(destinationSID[:], transposed)
			} else {
				copy(destinationSID[:], infoSubTLV.SID)
			}
		}
	}

	// map into EgressPolicies
	policies := []*srv6.EgressPolicy{}
	for _, bgpVRF := range bgpVRFs {
		for _, configuredRT := range bgpVRF.ImportRTs {
			// Path should match one of the configured import route targets.
			if configuredRT == RT {
				l.Debugf("Matched vrf %s route target with discovered route target %v", bgpVRF.VRFRef, RT)

				// find IsovalentVRF instance corresponding to matched vrf
				vrf, exists := r.SRv6Manager.GetVRFByName(k8sTypes.NamespacedName{Name: bgpVRF.VRFRef})
				if !exists {
					l.Debugf("VRF %s does not exist in SRv6 Manager", bgpVRF.VRFRef)
					continue
				}

				policy := &srv6.EgressPolicy{
					VRFID:    vrf.VRFID,
					DstCIDRs: prefixes,
					SID:      destinationSID,
				}
				policies = append(policies, policy)
				l.WithField("policy", policy).Debug("Mapped VPNv4 route to policy.")
			}
		}
	}

	return policies, nil
}

// TransposeSID will return a 128 bit array repsenting an SRv6 SID after transposing
// a defined number of bits from the provided MPLS label.
//
// Per RFC: https://datatracker.ietf.org/doc/html/draft-ietf-bess-srv6-services-15#section-4
// When the TranspositionLengh field in the SRv6SIDSubStructureSubSubTLV is greater then 0
// the SRv6 SID must be obtained by transposing a variable bit range from the MPLS label
// within the VPNv4 NLRI. The bit ranges are provided by fields within the SRv6SIDSubStructureSubSubTLV.
func transposeSID(l logrus.FieldLogger, label uint32, infoTLV *bgp.SRv6InformationSubTLV, structTLV *bgp.SRv6SIDStructureSubSubTLV) ([]byte, error) {
	// must shift label by twelve, not sure if this is something with frr or not.
	label = label << 12

	off := structTLV.TranspositionOffset // number of bits into the SID where transposition starts
	le := structTLV.TranspositionLength  // length in bits of transposition
	sid := infoTLV.SID

	l.WithFields(logrus.Fields{
		"label":       fmt.Sprintf("%x", label),
		"offset":      off,
		"length":      le,
		"originalSid": fmt.Sprintf("%x", sid),
		"startByte":   off / 8,
	}).Debug("Starting SID transposition")
	for le > 0 {
		var (
			// current byte index to tranpose
			byteI = off / 8
			// current bit index where bit transposition will occur
			bitI = off % 8
			// number of bits that will be copied from label into sid.
			n = (8 - bitI)
		)
		// get to a byte boundary, then eat full bytes until we can't.
		if le >= 8 {
			mask := ^byte(0) << n
			sid[byteI] = ((sid[byteI] & mask) | byte(label>>(32-n)))
			label <<= n
			off = off + n
			le = le - n
			l.WithFields(logrus.Fields{
				"label":          fmt.Sprintf("%x", label),
				"nextOffset":     off,
				"length":         le,
				"copiedN":        n,
				"byteI":          fmt.Sprintf("%x", byteI),
				"bitI":           fmt.Sprintf("%x", bitI),
				"mask":           fmt.Sprintf("%x", mask),
				"transposedByte": fmt.Sprintf("%x", sid[byteI]),
			}).Debug("Transposed bits")
			continue
		}
		// deal with a final bit difference.
		mask := ^byte(0) >> le
		sid[byteI] = ((sid[byteI] & mask) | byte(label>>(32-le))) << (8 - le)
		l.WithFields(logrus.Fields{
			"label":          fmt.Sprintf("%x", label),
			"nextOffset":     off,
			"length":         le,
			"copiedN":        n,
			"byteI":          fmt.Sprintf("%x", byteI),
			"bitI":           fmt.Sprintf("%x", bitI),
			"mask":           fmt.Sprintf("%x", mask),
			"transposedByte": fmt.Sprintf("%x", sid[byteI]),
		}).Debug("Transposed bits")
	}
	l.Debugf("Transposed SID %x", sid)
	return sid, nil
}

// keyifySRv6Policy creates a string key for a SRv6PolicyConfig.
func keyifySRv6Policy(p *srv6.EgressPolicy) (string, error) {
	b := &bytes.Buffer{}

	id := strconv.FormatUint(uint64(p.VRFID), 10)
	if _, err := b.Write([]byte(id)); err != nil {
		return "", err
	}

	for _, cidr := range p.DstCIDRs {
		if _, err := b.Write([]byte(cidr.String())); err != nil {
			return "", err
		}
	}

	h := sha256.New()
	if _, err := io.Copy(h, b); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
