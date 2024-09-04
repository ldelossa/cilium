//nolint:goheader
//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package remoteproxy

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/cilium/hive/cell"

	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"
	proxytypes "github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"

	fqdnpb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "fqdnha/remoteproxy")
var fqdnHAControllerGroup = controller.NewGroup("fqdn-ha")

const (
	fqdnRelayController                    string = "fqdn-relay-controller"
	fqdnUpdateTimeout                             = 10 * time.Second
	fqdnRulesCacheKeysSize                 int    = 16
	fqdnRestoredRulesToRemoveCacheKeysSize int    = 16
)

// RemoteFQDNProxy is a gRPC client used to communicate with the external
// fqdn-proxy.
//
// It handles FQDN rules updates and send them to the remote fqdn-proxy
// via a gRPC connection. The updates are identified by their fqdnRuleKey key,
// which is also used to deduplicate them. This is done to reduce the gRPC
// calls from the proxy plugin to the external fqdn-proxy and to guarantee
// that the latest update version will be sent to the fqdn-proxy.
//
// the general flow is that update events are intercepted by the DoubleProxy, pushed
// to the local proxy, then pushed to the remote proxy. However, we first
// connect to the remote proxy, we need to replay all existing rules first.
//
// This is accomplished by looking at the current state of the local proxy
// and synthezising an update for all already-existing endpoints.
type RemoteFQDNProxy struct {
	lock   lock.Mutex // protects remote
	remote *remoteProxy
	local  *dnsproxy.DNSProxy

	done           chan struct{}
	localProxyChan chan *dnsproxy.DNSProxy
}

// UpdateAllowed is the primary event that we care about. It indicates that the supplied endpoint + port is allowed
// to make DNS requests to the set of destinations, optionally with a given set of regular expressions.
//
// Whenever an endpoint has a new or updated redirect, that event is sent to the local
// DNS proxy as well as here, so we can update the remote. This update is asynchronous;
// we queue it and have a synchronization controller.
func (r *RemoteFQDNProxy) UpdateAllowed(endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) error {
	rp := r.getRemote()
	if rp == nil {
		return nil // not connected, can skip update
	}

	// Filter out protocols that cannot apply to DNS.
	if proto := destPortProto.Protocol(); proto != uint8(u8proto.UDP) && proto != uint8(u8proto.TCP) {
		return nil
	}

	msg := ruleToMsg(endpointID, destPortProto, newRules)
	rp.enqueueFQDNRulesUpdate(msg)
	rp.trigger()

	return nil
}

func ruleToMsg(endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) *fqdnpb.FQDNRules {
	msg := &fqdnpb.FQDNRules{
		EndpointID: endpointID,
		DestPort:   uint32(destPortProto.Port()),
		DestProto:  uint32(destPortProto.Protocol()),
	}

	msg.Rules = &fqdnpb.L7Rules{
		SelectorRegexMapping:      make(map[string]string),
		SelectorIdentitiesMapping: make(map[string]*fqdnpb.IdentityList),
	}
	for selector, l7rules := range newRules {
		msg.Rules.SelectorRegexMapping[selector.String()] = dnsproxy.GeneratePattern(l7rules)
		nids := selector.GetSelections()
		ids := make([]uint32, len(nids))
		for i, nid := range nids {
			ids[i] = uint32(nid)
		}
		msg.Rules.SelectorIdentitiesMapping[selector.String()] = &fqdnpb.IdentityList{
			List: ids,
		}
	}
	return msg
}

// remoteProxy represents the actual connection to a live remote proxy.
// It contains the gRPC client as well as a queue of updates.
// When the proxy first connects, a bootstrap set of updates is sent
// from the existing state. Subsequent updates are queued.
//
// There is no need to queue updates while the client is disconnected; we will
// replay all known state upon successful connect.
type remoteProxy struct {
	ctx    context.Context
	cancel context.CancelFunc

	conn   *grpc.ClientConn
	client fqdnpb.FQDNProxyClient

	controllers *controller.Manager

	// To keep the insertion O(1) and preserve updates ordering,
	// we use both a slice and a map. The slice is responsible for
	// storing the update keys preserving the order in which they
	// arrive, while the map will associate each key to its update.
	fqdnRulesCacheKeys []fqdnRuleKey
	fqdnRulesCacheMap  map[fqdnRuleKey]*fqdnpb.FQDNRules

	// The set of endpoints that have been restored
	// and can have the restored rules removed
	fqdnRestoredRulesToRemoveCache map[uint16]struct{}

	// Both these queues must be protected
	queueLock lock.Mutex
}

// fqdnRuleKey is a helper structure to be used as a key to
// identify messages in the update allowed messages cache.
// The endpoint ID and the destination port are sufficient to
// uniquely identify each update without generating string based
// hashes that may lead to excessive memory pressure.
type fqdnRuleKey struct {
	endpointID    uint64
	destPortProto uint32
}

func msgKey(msg *fqdnpb.FQDNRules) fqdnRuleKey {
	pp := restore.PortProto(msg.DestPort)
	if msg.DestProto != 0 {
		pp = restore.MakeV2PortProto(uint16(msg.DestPort), u8proto.U8proto(msg.DestProto))
	}
	return fqdnRuleKey{msg.EndpointID, uint32(pp)}
}

func newRemoteFQDNProxy() *RemoteFQDNProxy {
	proxy := &RemoteFQDNProxy{
		done:           make(chan struct{}),
		localProxyChan: make(chan *dnsproxy.DNSProxy),
	}

	return proxy
}

// onConnect is called when the gRPC client successfully connects to the remote proxy.
//
// It dumps the current state of the system in order to bootstrap, queues this for forwarding, then
// starts handling update events.
func (r *RemoteFQDNProxy) onConnect(connection *grpc.ClientConn, client fqdnpb.FQDNProxyClient) {
	log.Info("Successfully connected to remote FQDN proxy, initializing...")

	rp := &remoteProxy{
		conn:                           connection,
		controllers:                    controller.NewManager(),
		client:                         client,
		fqdnRulesCacheKeys:             make([]fqdnRuleKey, 0, fqdnRulesCacheKeysSize),
		fqdnRulesCacheMap:              make(map[fqdnRuleKey]*fqdnpb.FQDNRules),
		fqdnRestoredRulesToRemoveCache: make(map[uint16]struct{}, fqdnRestoredRulesToRemoveCacheKeysSize),
	}

	rp.ctx, rp.cancel = context.WithCancel(context.Background())

	r.lock.Lock()
	defer r.lock.Unlock()
	// Need to keep this locked while setting up; block updates while dumping so we don't
	// miss any updates.

	// Dump all rules, enqueue them in the update
	state := r.local.DumpRules()
	for _, rules := range state {
		rp.enqueueFQDNRestoredRulesToRemove(uint16(rules.EndpointID))
		rp.enqueueFQDNRulesUpdate(rules)
	}

	log.Infof("Initialized FQDN proxy state with %d endpoints and %d rules", len(rp.fqdnRestoredRulesToRemoveCache), len(state))

	// Start controllers
	rp.controllers.UpdateController(
		fqdnRelayController,
		controller.ControllerParams{
			Context: rp.ctx,
			Group:   fqdnHAControllerGroup,
			DoFunc:  rp.forwardUpdates,
		},
	)

	r.remote = rp
}

func (r *RemoteFQDNProxy) onDisconnect() {
	log.Infof("Lost connection to remote FQDN proxy.")
	r.lock.Lock()
	rp := r.remote
	r.remote = nil
	r.lock.Unlock()

	if rp == nil {
		return
	}
	rp.cancel()
	rp.controllers.RemoveAll()
	if rp.conn != nil {
		rp.conn.Close()
	}
}

// Returns the active remote, or nil if disconnected
func (r *RemoteFQDNProxy) getRemote() *remoteProxy {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.remote
}

func (rp *remoteProxy) trigger() {
	if rp.ctx.Err() != nil {
		return
	}
	rp.controllers.TriggerController(fqdnRelayController)
}

type params struct {
	cell.In

	L7Proxy *proxy.Proxy
	Cfg     fqdnhaconfig.Config
}

func NewRemoteFQDNProxy(
	lc cell.Lifecycle,
	p params,
) (*RemoteFQDNProxy, error) {
	if !p.Cfg.EnableExternalDNSProxy {
		return nil, nil
	}
	remoteProxy := newRemoteFQDNProxy()
	err := p.L7Proxy.SetProxyPort(proxytypes.DNSProxyName, proxytypes.ProxyTypeDNS, 10001, false)
	if err != nil {
		return nil, fmt.Errorf("can't set proxy port: %w", err)
	}
	lc.Append(remoteProxy)
	return remoteProxy, nil
}

// Once the doubeproxy has initialized, it will provide us the local proxy
func (r *RemoteFQDNProxy) ProvideLocalProxy(lp *dnsproxy.DNSProxy) {
	r.localProxyChan <- lp
}

func (r *RemoteFQDNProxy) Start(_ cell.HookContext) error {
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-r.done
			cancel()
		}()

		// Wait for the DoubleProxy to initialize
		select {
		case <-r.done:
			return
		case p := <-r.localProxyChan:
			r.local = p
		}

		timer, done := inctimer.New()
		defer done()
		for {
			log.Debug("trying to connect to remote proxy...")
			// create a new connection from the agent to the remote fqdn proxy
			var err error
			connection, err := grpc.DialContext(ctx, "unix:///var/run/cilium/proxy.sock", grpc.WithInsecure(), grpc.WithBlock())
			if err != nil {
				log.WithError(err).Error("Failed to dial remote proxy server")
			} else {
				r.onConnect(connection, fqdnpb.NewFQDNProxyClient(connection))
				// Block while connection is ready
				connection.WaitForStateChange(ctx, connectivity.Ready)
				log.WithField(logfields.State, connection.GetState()).Info("FQDN remote proxy connection state changed")
				r.onDisconnect()
			}

			select {
			case <-r.done:
				return
			case <-timer.After(30 * time.Second):
				continue
			}
		}
	}()
	return nil
}

func (r *RemoteFQDNProxy) Stop(ctx cell.HookContext) error {
	close(r.done)
	log.Info("FQDN HA proxy stopped")
	return nil
}

func (r *RemoteFQDNProxy) RemoveRestoredRules(endpointID uint16) {
	rp := r.getRemote()
	if rp == nil {
		return // not connected
	}
	rp.enqueueFQDNRestoredRulesToRemove(endpointID)
	rp.trigger()
}

func (rp *remoteProxy) forwardUpdates(ctx context.Context) error {
	start := time.Now()
	if err := rp.forwardFQDNRulesUpdates(ctx); err != nil {
		return err
	}
	if err := rp.forwardFQDNRestoredRulesToRemoveUpdates(ctx); err != nil {
		return err
	}
	log.WithField(logfields.Duration, time.Since(start)).Debugf("Successfully synchronized FQDN rules with remote proxy")
	return nil
}

func (rp *remoteProxy) enqueueFQDNRestoredRulesToRemove(msg uint16) {
	rp.queueLock.Lock()
	defer rp.queueLock.Unlock()

	rp.fqdnRestoredRulesToRemoveCache[msg] = struct{}{}
}

func (rp *remoteProxy) drainFQDNRestoredRulesToRemove() map[uint16]struct{} {
	rp.queueLock.Lock()
	defer rp.queueLock.Unlock()

	queue := rp.fqdnRestoredRulesToRemoveCache
	rp.fqdnRestoredRulesToRemoveCache = make(map[uint16]struct{}, fqdnRestoredRulesToRemoveCacheKeysSize)
	return queue
}

func (rp *remoteProxy) forwardFQDNRestoredRulesToRemoveUpdates(ctx context.Context) error {
	toProcess := rp.drainFQDNRestoredRulesToRemove()
	defer func() {
		if len(toProcess) > 0 {
			rp.queueLock.Lock()
			defer rp.queueLock.Unlock()

			maps.Copy(rp.fqdnRestoredRulesToRemoveCache, toProcess)
		}
	}()

	for endpointID := range toProcess {
		if err := ctx.Err(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, fqdnUpdateTimeout)
		defer cancel()

		if _, err := rp.client.RemoveRestoredRules(ctx, &fqdnpb.EndpointID{EndpointID: uint32(endpointID)}); err != nil {
			return fmt.Errorf("failed to forward FQDN restored endpoint to remove to remote proxy for endpointID %d: %w", endpointID, err)
		}
		delete(toProcess, endpointID)
		log.WithFields(logrus.Fields{logfields.EndpointID: endpointID}).Info("Removed restored rules completed")
	}

	return nil
}

func (rp *remoteProxy) enqueueFQDNRulesUpdate(msg *fqdnpb.FQDNRules) {
	rp.queueLock.Lock()
	defer rp.queueLock.Unlock()

	key := msgKey(msg)
	if _, ok := rp.fqdnRulesCacheMap[key]; !ok {
		rp.fqdnRulesCacheKeys = append(rp.fqdnRulesCacheKeys, key)
	}
	// overwrite stale updates with the same fqdn rules message key
	rp.fqdnRulesCacheMap[key] = msg
}

func (rp *remoteProxy) drainFQDNRulesUpdate() (keys []fqdnRuleKey, msgs map[fqdnRuleKey]*fqdnpb.FQDNRules) {
	rp.queueLock.Lock()
	defer rp.queueLock.Unlock()

	keys = rp.fqdnRulesCacheKeys
	msgs = rp.fqdnRulesCacheMap

	rp.fqdnRulesCacheKeys = make([]fqdnRuleKey, 0, fqdnRulesCacheKeysSize)
	rp.fqdnRulesCacheMap = make(map[fqdnRuleKey]*fqdnpb.FQDNRules, fqdnRulesCacheKeysSize)

	return keys, msgs
}

func (rp *remoteProxy) prependFQDNRulesUpdates(keysToProcess []fqdnRuleKey, msgsToProcess map[fqdnRuleKey]*fqdnpb.FQDNRules) {
	rp.queueLock.Lock()
	defer rp.queueLock.Unlock()

	rp.fqdnRulesCacheKeys = slices.DeleteFunc(rp.fqdnRulesCacheKeys, func(k fqdnRuleKey) bool {
		_, ok := msgsToProcess[k]
		return ok
	})

	rp.fqdnRulesCacheKeys = slices.Concat(keysToProcess, rp.fqdnRulesCacheKeys)

	for key, msg := range msgsToProcess {
		if _, ok := rp.fqdnRulesCacheMap[key]; !ok {
			rp.fqdnRulesCacheMap[key] = msg
		}
	}
}

func (rp *remoteProxy) forwardFQDNRulesUpdates(ctx context.Context) error {
	keysToProcess, msgsToProcess := rp.drainFQDNRulesUpdate()
	defer func() {
		if len(keysToProcess) > 0 {
			rp.prependFQDNRulesUpdates(keysToProcess, msgsToProcess)
		}
	}()

	for len(keysToProcess) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, fqdnUpdateTimeout)
		defer cancel()

		key := keysToProcess[0]
		msg := msgsToProcess[key]

		if _, err := rp.client.UpdateAllowed(ctx, msg); err != nil {
			log.WithFields(logrus.Fields{
				"newRules":           msg.Rules,
				logfields.EndpointID: msg.EndpointID,
			}).WithError(err).Error("Failed to forward FQDN rules update to remote proxy")
			return err
		}
		log.WithFields(logrus.Fields{
			"newRules":           msg.Rules,
			logfields.EndpointID: msg.EndpointID,
		}).Debug("Forwarded UpdateAllowed() to remote FQDN proxy")
		keysToProcess = keysToProcess[1:]
		delete(msgsToProcess, key)
	}

	return nil
}

func (r *RemoteFQDNProxy) Cleanup() {
	r.onDisconnect()
}

func (r *RemoteFQDNProxy) GetBindPort() uint16 {
	//TODO: don't hardcode that
	return 10001
}

func (r *RemoteFQDNProxy) SetRejectReply(_ string) {
	//TODO: allow agent to do it or get it from config in proxy pod?
}

func (r *RemoteFQDNProxy) RestoreRules(op *endpoint.Endpoint) {
	//TODO: implement that
}
