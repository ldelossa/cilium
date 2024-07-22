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
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	srv6 "github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/option"
)

type PodCIDRVRFReconcilerIn struct {
	cell.In

	Logger       logrus.FieldLogger
	Group        job.Group
	DaemonConfig *option.DaemonConfig
	Config       config.Config
	Adverts      *IsovalentAdvertisement
	Upgrader     paramUpgrader
	SRv6Paths    *srv6Paths
	SRv6Manager  *srv6.Manager
}

type PodCIDRVRFReconcilerOut struct {
	cell.Out

	Reconciler reconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type PodCIDRVRFReconciler struct {
	Logger      logrus.FieldLogger
	Adverts     *IsovalentAdvertisement
	Upgrader    paramUpgrader
	SRv6Paths   *srv6Paths
	SRv6Manager SRv6Manager
}

type PodCIDRVRFReconcilerMetadata struct {
	VRFAFPaths reconcilerv2.ResourceAFPathsMap
}

func NewPodCIDRVRFReconciler(in PodCIDRVRFReconcilerIn) PodCIDRVRFReconcilerOut {
	// Don't provide the reconciler if the SRv6 manager or Enterprise BGP is not enabled
	if !in.Config.Enabled || !in.DaemonConfig.EnableSRv6 {
		return PodCIDRVRFReconcilerOut{}
	}

	// Don't provide the reconciler if the IPAM mode is not supported
	if !types.CanAdvertisePodCIDR(in.DaemonConfig.IPAMMode()) {
		in.Logger.Info("Unsupported IPAM mode, disabling PodCIDR VPN advertisements.")
		return PodCIDRVRFReconcilerOut{}
	}

	pr := &PodCIDRVRFReconciler{
		Logger:      in.Logger.WithField(types.ReconcilerLogField, "pod-cidr-vrf"),
		Adverts:     in.Adverts,
		Upgrader:    in.Upgrader,
		SRv6Paths:   in.SRv6Paths,
		SRv6Manager: in.SRv6Manager,
	}

	return PodCIDRVRFReconcilerOut{Reconciler: pr}
}

func (r *PodCIDRVRFReconciler) Name() string {
	return "PodCIDRVRFReconciler"
}

func (r *PodCIDRVRFReconciler) Priority() int {
	return 31 // somewhere around OSS PodCIDR Reconciler
}

func (r *PodCIDRVRFReconciler) Reconcile(ctx context.Context, p reconcilerv2.ReconcileParams) error {
	iParams, err := r.Upgrader.upgrade(p)
	if err != nil {
		if errors.Is(err, NotInitializedErr) {
			r.Logger.Debug("Initialization is not done, skipping pod CIDR VPN reconciliation")
			return nil
		}
		return err
	}

	// get pod CIDRs
	podCIDRPrefixes, err := r.getPodCIDRs(iParams.CiliumNode)
	if err != nil {
		return err
	}

	// get PodCIDR VPN advertisements
	desiredVRFAdverts, err := r.Adverts.GetConfiguredVRFAdvertisements(iParams.DesiredConfig, v1alpha1.BGPPodCIDRAdvert)
	if err != nil {
		return err
	}

	return r.reconcilePaths(ctx, iParams, podCIDRPrefixes, desiredVRFAdverts)
}

func (r *PodCIDRVRFReconciler) getPodCIDRs(cn *ciliumv2.CiliumNode) ([]netip.Prefix, error) {
	if cn == nil {
		return nil, fmt.Errorf("CiliumNode is nil")
	}

	var podCIDRPrefixes []netip.Prefix
	for _, cidr := range cn.Spec.IPAM.PodCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse prefix %s: %w", cidr, err)
		}
		podCIDRPrefixes = append(podCIDRPrefixes, prefix)
	}

	return podCIDRPrefixes, nil
}

func (r *PodCIDRVRFReconciler) reconcilePaths(ctx context.Context, p EnterpriseReconcileParams, podCIDRPrefixes []netip.Prefix, desiredVRFAdverts VRFAdvertisements) error {
	allVRFsPodCIDRAFPaths, err := r.getDesiredVRFAFPaths(p, podCIDRPrefixes, desiredVRFAdverts)
	if err != nil {
		return err
	}

	metadata := r.getMetadata(p.BGPInstance)
	for vrfKey, desiredVRFPodCIDRAFPaths := range allVRFsPodCIDRAFPaths {
		currentVRFPodCIDRAFPaths, exists := metadata.VRFAFPaths[vrfKey]
		if !exists && len(desiredVRFPodCIDRAFPaths) == 0 {
			// no paths to reconcile for this VRF
			continue
		}

		updatedVRFAfPaths, rErr := reconcilerv2.ReconcileAFPaths(&reconcilerv2.ReconcileAFPathsParams{
			Logger: r.Logger.WithFields(
				logrus.Fields{
					types.InstanceLogField: p.DesiredConfig.Name,
					entTypes.VRFLogField:   vrfKey,
				}),
			Ctx:          ctx,
			Router:       p.BGPInstance.Router,
			DesiredPaths: desiredVRFPodCIDRAFPaths,
			CurrentPaths: currentVRFPodCIDRAFPaths,
		})
		if rErr == nil && len(desiredVRFPodCIDRAFPaths) == 0 {
			delete(metadata.VRFAFPaths, vrfKey)
		} else {
			metadata.VRFAFPaths[vrfKey] = updatedVRFAfPaths
		}
		err = errors.Join(err, rErr)
	}

	r.setMetadata(p.BGPInstance, metadata)

	return err
}

func (r *PodCIDRVRFReconciler) getDesiredVRFAFPaths(p EnterpriseReconcileParams, podCIDRPrefixes []netip.Prefix, desiredVRFAdverts VRFAdvertisements) (reconcilerv2.ResourceAFPathsMap, error) {
	desiredVRFsAFPaths := make(reconcilerv2.ResourceAFPathsMap)

	metadata := r.getMetadata(p.BGPInstance)

	// check if IsovalentVRF is deleted or removed from desired config
	for vrfNamespacedName := range metadata.VRFAFPaths {
		_, exists := r.SRv6Manager.GetVRFByName(k8sTypes.NamespacedName{Name: vrfNamespacedName.Name, Namespace: vrfNamespacedName.Namespace})
		if !exists {
			// vrf is deleted, mark it for removal
			desiredVRFsAFPaths[vrfNamespacedName] = nil
			continue
		}

		found := false
		for _, bgpVRF := range p.DesiredConfig.VRFs {
			bgpVRFKey := resource.Key{Name: bgpVRF.VRFRef}
			if vrfNamespacedName == bgpVRFKey {
				found = true
				break
			}
		}
		if !found {
			// vrf is deleted from desired config, mark it for removal
			desiredVRFsAFPaths[vrfNamespacedName] = nil
		}
	}

	for _, bgpVRF := range p.DesiredConfig.VRFs {
		// check if pod CIDR advertisement is configured for this BGP VRF
		afAdverts, exists := desiredVRFAdverts[bgpVRF.VRFRef]
		if !exists {
			continue
		}

		// get isoVRF resource
		_, exists = r.SRv6Manager.GetVRFByName(k8sTypes.NamespacedName{Name: bgpVRF.VRFRef})
		if !exists {
			r.Logger.WithField(entTypes.VRFLogField, bgpVRF.VRFRef).Warn("VRF not found in SRv6 Manager")
			continue
		}

		desiredVRFAFPaths := make(reconcilerv2.AFPathsMap)
		for fam, adverts := range afAdverts {
			family := types.ToAgentFamily(fam)

			// we do not care about advertisements for pod CIDRs, as long as there is one,
			// we will advertise the pod CIDRs
			if len(adverts) == 0 {
				continue
			}

			for _, prefix := range podCIDRPrefixes {
				if prefix.Addr().Is4() && family.Afi == types.AfiIPv4 {
					path, pathKey, err := r.SRv6Paths.GetSRv6VPNPath(prefix, bgpVRF)
					if err != nil {
						r.Logger.WithError(err).WithField("prefix", prefix).Error("failed to get SRv6 paths for prefix")
						continue
					}
					path.Family = family
					reconcilerv2.AddPathToAFPathsMap(desiredVRFAFPaths, family, path, pathKey)
				}

				if prefix.Addr().Is6() && family.Afi == types.AfiIPv6 {
					path, pathKey, err := r.SRv6Paths.GetSRv6VPNPath(prefix, bgpVRF)
					if err != nil {
						r.Logger.WithError(err).WithField("prefix", prefix).Error("failed to get SRv6 paths for prefix")
						continue
					}
					path.Family = family
					reconcilerv2.AddPathToAFPathsMap(desiredVRFAFPaths, family, path, pathKey)
				}
			}
		}
		desiredVRFsAFPaths[resource.Key{Name: bgpVRF.VRFRef}] = desiredVRFAFPaths
	}
	return desiredVRFsAFPaths, nil
}

func (r *PodCIDRVRFReconciler) getMetadata(i *EnterpriseBGPInstance) PodCIDRVRFReconcilerMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = PodCIDRVRFReconcilerMetadata{
			VRFAFPaths: make(reconcilerv2.ResourceAFPathsMap),
		}
	}
	return i.Metadata[r.Name()].(PodCIDRVRFReconcilerMetadata)
}

func (r *PodCIDRVRFReconciler) setMetadata(i *EnterpriseBGPInstance, metadata PodCIDRVRFReconcilerMetadata) {
	i.Metadata[r.Name()] = metadata
}
