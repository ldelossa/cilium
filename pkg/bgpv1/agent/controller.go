// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"

	"github.com/cilium/workerpool"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ip"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeaddr "github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	srv6 "github.com/cilium/cilium/pkg/srv6"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bgp-control-plane")
)

var (
	// ErrMultiplePolicies is a static error typed when the controller encounters
	// multiple policies which apply to its host.
	ErrMultiplePolicies = fmt.Errorf("more then one CiliumBGPPeeringPolicy applies to this node, please ensure only a single Policy matches this node's labels")
	ErrSRv6NoMgr        = fmt.Errorf("a virtual router requests the mapping of SRv6 VRFs but no SRv6 Manager exists")
)

// Signaler multiplexes multiple event sources into a single level-triggered
// event.
//
// Signaler should always be constructed with a channel of size 1.
//
// Use of a Signaler allows for bursts of events to be "rolled-up".
// This is a suitable approach since the Controller checks the entire state of
// the world on each iteration of its control loop.
//
// Additionally, this precludes any need for ordering between different event
// sources.
type Signaler struct {
	Sig chan struct{}
}

// NewSignaler constructs a Signaler
func NewSignaler() Signaler {
	return Signaler{
		Sig: make(chan struct{}, 1),
	}
}

// Event adds an edge triggered event to the Signaler.
//
// A controller which uses this Signaler will be notified of this event some
// time after.
//
// This signature adheres to the common event handling signatures of
// cache.ResourceEventHandlerFuncs for convenience.
func (s Signaler) Event(_ interface{}) {
	select {
	case s.Sig <- struct{}{}:
	default:
	}
}

// ControlPlaneState captures a subset of Cilium's runtime state.
//
// This state carries information interesting to various BGP sub-systems
// and provides a contract for information a sub-system will be provided
// about Cilium's runtime state.
//
// ControlPlaneState should be a point-in-time snapshot of Cilium's runtime
// state and remain read-only to all sub systems its passed to.
type ControlPlaneState struct {
	// A list of configured PodCIDRs for the current Node.
	PodCIDRs []string
	// Parsed 'cilium.io/bgp-virtual-router' annotations of the the node this
	// control plane is running on.
	Annotations AnnotationMap
	// The current IPv4 address of the agent, reachable externally.
	IPv4 netip.Addr
	// The current IPv6 address of the agent, reachable externally.
	IPv6 netip.Addr
	// The VRFs present at the time of BGP control plane reconciliation.
	VRFs []srv6.VRF
	// The Signaler attached to the BGP control plane used to signal reconciliation
	Sig *Signaler
}

// ResolveRouterID resolves router ID, if we have an annotation and it can be
// parsed into a valid ipv4 address use it. If not, determine if Cilium is
// configured with an IPv4 address, if so use it. If neither, return an error,
// we cannot assign an router ID.
func (cstate *ControlPlaneState) ResolveRouterID(localASN int) (string, error) {
	if _, ok := cstate.Annotations[localASN]; ok {
		if parsed, err := netip.ParseAddr(cstate.Annotations[localASN].RouterID); err == nil && !parsed.IsUnspecified() {
			return parsed.String(), nil
		}
	}

	if !cstate.IPv4.IsUnspecified() {
		return cstate.IPv4.String(), nil
	}

	return "", fmt.Errorf("router id not specified by annotation and no IPv4 address assigned by cilium, cannot resolve router id for virtual router with local ASN %v", localASN)
}

type policyLister interface {
	List() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error)
}

type policyListerFunc func() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error)

func (plf policyListerFunc) List() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error) {
	return plf()
}

// SRv6Interface is the expected method set for interfacing with Cilium's
// SRv6 control and data planes.
type SRv6Interface interface {
	GetAllVRFs() []*srv6.VRF
	GetVRFs(importRouteTarget string) []*srv6.VRF
	GetEgressPolicies() []*srv6.EgressPolicy
}

// Controller is the agent side BGP Control Plane controller.
//
// Controller listens for events and drives BGP related sub-systems
// to maintain a desired state.
type Controller struct {
	NodeSpec nodeSpecer
	// PolicyResource provides a store of cached policies and allows us to observe changes to the objects in its
	// store.
	PolicyResource resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy]
	// PolicyLister is an interface which allows for the listing of all known policies
	PolicyLister policyLister
	// Sig informs the Controller that a Kubernetes
	// event of interest has occurred.
	//
	// The signal itself provides no other information,
	// when it occurs the Controller will query each
	// informer for the latest API information required
	// to drive it's control loop.
	Sig Signaler
	// BGPMgr is an implementation of the BGPRouterManager interface
	// and provides a declarative API for configuring BGP peers.
	BGPMgr BGPRouterManager

	srv6Mu lock.RWMutex
	// SRv6 is an implementation of the expected method set for interfacing with
	// Cilium's SRv6 control and data planes.
	SRv6 SRv6Interface

	// Client set for writing SRv6 egress policies back to K8s.
	Clientset k8sClient.Clientset

	workerpool *workerpool.WorkerPool

	// Shutdowner can be used to trigger a shutdown of hive
	Shutdowner hive.Shutdowner
}

// ControllerParams contains all parameters needed to construct a Controller
type ControllerParams struct {
	cell.In

	Lifecycle      hive.Lifecycle
	Shutdowner     hive.Shutdowner
	Sig            Signaler
	RouteMgr       BGPRouterManager
	PolicyResource resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy]
	DaemonConfig   *option.DaemonConfig
	NodeSpec       nodeSpecer
	Clientset      k8sClient.Clientset
}

// NewController constructs a new BGP Control Plane Controller.
//
// When the constructor returns the Controller will be actively watching for
// events and configuring BGP related sub-systems.
//
// The constructor requires an implementation of BGPRouterManager to be provided.
// This implementation defines which BGP backend will be used (GoBGP, FRR, Bird, etc...)
// NOTE: only GoBGP currently implemented.
func NewController(params ControllerParams) (*Controller, error) {
	// If the BGP control plane is disabled, just return nil. This way the hive dependency graph is always static
	// regardless of config. The lifecycle has not been appended so no work will be done.
	if !params.DaemonConfig.BGPControlPlaneEnabled() {
		return nil, nil
	}

	c := Controller{
		Sig:            params.Sig,
		BGPMgr:         params.RouteMgr,
		PolicyResource: params.PolicyResource,
		NodeSpec:       params.NodeSpec,
		Shutdowner:     params.Shutdowner,
		Clientset:      params.Clientset,
	}

	params.Lifecycle.Append(&c)

	return &c, nil
}

// Start is called by hive after all of our dependencies have been started.
func (c *Controller) Start(startCtx hive.HookContext) error {
	store, err := c.PolicyResource.Store(startCtx)
	if err != nil {
		return fmt.Errorf("PolicyResource.Store(): %w", err)
	}
	c.PolicyLister = policyListerFunc(func() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error) {
		return store.List(), nil
	})

	c.workerpool = workerpool.New(2)

	c.workerpool.Submit("policy-observer", func(ctx context.Context) error {
		for ev := range c.PolicyResource.Events(ctx) {
			switch ev.Kind {
			case resource.Upsert, resource.Delete:
				// Signal the reconciliation logic.
				c.Sig.Event(struct{}{})
			}
			ev.Done(nil)
		}
		return nil
	})

	c.workerpool.Submit("controller", func(ctx context.Context) error {
		c.Run(ctx)
		return nil
	})

	return nil
}

// Stop is called by hive upon shutdown, after all of our dependants have been stopped.
// We should perform a graceful shutdown and return as soon as done or when the stop context is done.
func (c *Controller) Stop(ctx hive.HookContext) error {
	doneChan := make(chan struct{})
	go func() {
		c.workerpool.Close()
		close(doneChan)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-doneChan:
	}

	return nil
}

// Signal provides a thread-safe way to trigger the BGP Control Plane controller's
// reconciliation loop.
//
// It is guaranteed, bar any fatal errors, that the reconciliation loop is ran
// sometime after this method returns.
func (c *Controller) Signal() {
	c.Sig.Event(struct{}{})
}

func (c *Controller) SetSRv6Manager(srv6 SRv6Interface) {
	c.srv6Mu.Lock()
	c.SRv6 = srv6
	c.srv6Mu.Unlock()
}

// Run places the Controller into its control loop.
//
// Kubernetes shared informers are started just before entering the long running
// loop.
//
// When new events trigger a signal the control loop will be evaluated.
//
// A cancel of the provided ctx will kill the control loop along with the running
// informers.
func (c *Controller) Run(ctx context.Context) {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "Controller.Run",
		})
	)
	l.Debug("Starting informers")

	// add an initial signal to kick things off
	c.Sig.Event(struct{}{})

	l.Info("Cilium BGP Control Plane Controller now running...")
	for {
		select {
		case <-ctx.Done():
			killCTX, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			c.FullWithdrawal(killCTX) // kill any BGP sessions

			l.Info("Cilium BGP Control Plane Controller shut down")
			return
		case <-c.Sig.Sig:
			l.Info("Cilium BGP Control Plane Controller woken for reconciliation")
			if err := c.Reconcile(ctx); err != nil {
				l.WithError(err).Error("Encountered error during reconciliation")
			} else {
				l.Debug("Successfully completed reconciliation")
			}
		}
	}
}

// PolicySelection returns a CiliumBGPPeeringPolicy which applies to the provided
// *corev1.Node, enforced by a set of policy selection rules.
//
// Policy selection follows the following rules:
//   - A policy matches a node if said policy's "nodeSelector" field matches
//     the node's labels
//   - If (N > 1) policies match the provided *corev1.Node an error is returned.
//     only a single policy may apply to a node to avoid ambiguity at this stage
//     of development.
func (c *Controller) PolicySelection(ctx context.Context, labels map[string]string, policies []*v2alpha1api.CiliumBGPPeeringPolicy) (*v2alpha1api.CiliumBGPPeeringPolicy, error) {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "PolicySelection",
		})
	)

	// determine which policies match our node's labels.
	var (
		selected   *v2alpha1api.CiliumBGPPeeringPolicy
		slimLabels = slimlabels.Set(labels)
	)

	// range over policies and see if any match this node's labels.
	//
	// for now, only a single BGP policy can be applied to a node. if more then
	// one policy applies to a node, we disconnect from all BGP peers and log
	// an error.
	for _, policy := range policies {
		nodeSelector, err := slimmetav1.LabelSelectorAsSelector(policy.Spec.NodeSelector)
		if err != nil {
			l.WithError(err).Error("Failed to convert CiliumBGPPeeringPolicy's NodeSelector to a label.Selector interface")
		}
		l.WithFields(logrus.Fields{
			"policyNodeSelector": nodeSelector.String(),
			"nodeLabels":         slimLabels,
		}).Debug("Comparing BGP policy node selector with node's labels")
		if nodeSelector.Matches(slimLabels) {
			if selected != nil {
				return nil, ErrMultiplePolicies
			}
			selected = policy
		}
	}

	// we need to confirm we have a valid SRv6Mgr if any virtual router wants
	// to map SRv6VRFs
	if selected != nil {
		// lock on reading c.SRv6 pointer.
		c.srv6Mu.RLock()
		for _, vr := range selected.Spec.VirtualRouters {
			if vr.MapSRv6VRFs && (c.SRv6 == nil) {
				c.srv6Mu.RUnlock()
				return nil, ErrSRv6NoMgr
			}
		}
		c.srv6Mu.RUnlock()
	}

	return selected, nil
}

// Reconcile is the control loop for the Controller.
//
// Reconcile will be invoked when one or more event sources trigger a signal
// via the Controller's Signaler structure.
//
// On signal, Reconcile will obtain the state of the world necessary to drive
// the BGP control plane toward any new BGP peering policies.
//
// Reconcile will only allow a single CiliumBGPPeeringPolicy to apply to the
// node its running on.
func (c *Controller) Reconcile(ctx context.Context) error {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "Controller.Reconcile",
		})
	)

	// retrieve all CiliumBGPPeeringPolicies
	policies, err := c.PolicyLister.List()
	if err != nil {
		return fmt.Errorf("failed to list CiliumBGPPeeringPolicies")
	}
	l.WithField("count", len(policies)).Debug("Successfully listed CiliumBGPPeeringPolicies")

	// perform policy selection based on node.
	labels, err := c.NodeSpec.Labels()
	if err != nil {
		return fmt.Errorf("failed to retrieve labels for Node: %w", err)
	}
	policy, err := c.PolicySelection(ctx, labels, policies)
	if err != nil {
		l.WithError(err).Error("Policy selection failed")
		c.FullWithdrawal(ctx)
		return err
	}
	if policy == nil {
		// no policy was discovered, tell router manager to withdrawal peers if
		// they are configured.
		l.Debug("No BGP peering policy applies to this node, any existing BGP sessions will be removed.")
		c.FullWithdrawal(ctx)
		return nil
	}

	// parse any virtual router specific attributes defined on this node via
	// kubernetes annotations
	//
	// if we notice one or more malformed annotations report the errors up and
	// fail reconciliation.
	annotations, err := c.NodeSpec.Annotations()
	if err != nil {
		return fmt.Errorf("failed to retrieve Node's annotations: %w", err)
	}

	annoMap, err := NewAnnotationMap(annotations)
	if err != nil {
		return fmt.Errorf("failed to parse annotations: %w", err)
	}

	podCIDRs, err := c.NodeSpec.PodCIDRs()
	if err != nil {
		return fmt.Errorf("failed to retrieve Node's pod CIDR ranges: %w", err)
	}

	ipv4, _ := ip.AddrFromIP(nodeaddr.GetIPv4())
	ipv6, _ := ip.AddrFromIP(nodeaddr.GetIPv6())

	// define our current point-in-time control plane state.
	state := &ControlPlaneState{
		PodCIDRs:    podCIDRs,
		Annotations: annoMap,
		IPv4:        ipv4,
		IPv6:        ipv6,
		Sig:         &c.Sig,
	}

	// call bgp sub-systems required to apply this policy's BGP topology.
	l.Debug("Asking configured BGPRouterManager to configure peering")
	if err := c.BGPMgr.ConfigurePeers(ctx, policy, state); err != nil {
		return fmt.Errorf("failed to configure BGP peers, cannot apply BGP peering policy: %w", err)
	}

	// if we are the SRv6 responder handle this
	for asn, attr := range annoMap {
		if attr.SRv6Responder {
			log.Infof("Acting as SRv6 responder for local ASN %d", asn)

			// confirm we have a valid SRv6Manager pointer before reconciling.
			c.srv6Mu.RLock()
			if c.SRv6 == nil {
				c.srv6Mu.RUnlock()
				return fmt.Errorf("acting as SRv6 Responder but nil handle to SRv6 Manager")
			}
			c.srv6Mu.RUnlock()

			err := c.reconcileSRv6(ctx)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// keyifySRv6Policy creates a string key for a SRv6PolicyConfig.
func keyifySRv6Policy(p *srv6.EgressPolicy) string {
	b := &bytes.Buffer{}

	id := strconv.FormatUint(uint64(p.VRFID), 10)
	b.Write([]byte(id))

	for _, cidr := range p.DstCIDRs {
		b.Write([]byte(cidr.String()))
	}

	h := sha256.New()
	io.Copy(h, b)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (c *Controller) reconcileSRv6(ctx context.Context) error {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "Controller.reconcileSRv6",
			},
		)
		toCreate []*srv6.EgressPolicy
		toRemove []*srv6.EgressPolicy
	)
	l.Debug("Starting SRv6 egress policy reconciliation.")

	vrfs := c.SRv6.GetAllVRFs()
	l.WithField("count", len(vrfs)).Debug("Discovered configured VRFs")

	curPolicies := c.SRv6.GetEgressPolicies()
	l.WithField("count", len(curPolicies)).Debug("Discovered current egress policies")

	newPolicies, err := c.BGPMgr.MapSRv6EgressPolicy(ctx, vrfs)
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
			key = keyifySRv6Policy(p)
			h   *member
			ok  bool
		)
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
			key = keyifySRv6Policy(p)
			h   *member
			ok  bool
		)
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
	l.WithField("count", len(toCreate)).Info("Number of SRv6 egress policies to create.")
	l.WithField("count", len(toRemove)).Info("Number of SRv6 egress policies to remove.")

	clientSet := c.Clientset.CiliumV2alpha1().CiliumSRv6EgressPolicies()

	mkName := func(p *srv6.EgressPolicy) string {
		const (
			prefix = "bgp-control-plane"
		)
		return fmt.Sprintf("%s-%s", prefix, keyifySRv6Policy(p))
	}

	for _, p := range toCreate {
		destCIDRs := []v2alpha1api.CIDR{}
		for _, c := range p.DstCIDRs {
			destCIDRs = append(destCIDRs, v2alpha1api.CIDR(c.String()))
		}

		egressPol := &v2alpha1api.CiliumSRv6EgressPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: mkName(p),
			},
			TypeMeta: metav1.TypeMeta{
				APIVersion: "cilium.io/v2alpha1",
				Kind:       "CiliumSRv6EgressPolicy",
			},
			Spec: v2alpha1api.CiliumSRv6EgressPolicySpec{
				VRFID:            p.VRFID,
				DestinationCIDRs: []v2alpha1api.CIDR(destCIDRs),
				DestinationSID:   p.SID.IP().String(),
			},
		}
		l.WithField("policy", egressPol).Debug("Writing egress policy to Kubernetes")
		res, err := clientSet.Create(ctx, egressPol, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to write egress policy to Kubernetes: %w", err)
		}
		l.WithField("policy", res).Debug("Resulting egress policy")
	}

	for _, p := range toRemove {
		l.WithField("policy", p).Debug("Removing egress policy from Kubernetes")
		err := clientSet.Delete(ctx, mkName(p), metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("failed to remove egress policy: %w", err)
		}
	}

	return nil
}

// FullWithdrawal will instruct the configured BGPRouterManager to withdraw all
// BGP servers and peers.
func (c *Controller) FullWithdrawal(ctx context.Context) {
	_ = c.BGPMgr.ConfigurePeers(ctx, nil, nil) // cannot fail, no need for error handling
}
