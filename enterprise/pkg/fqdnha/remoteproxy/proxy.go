// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remoteproxy

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy"
	proxytypes "github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/time"

	fqdnpb "github.com/isovalent/fqdn-proxy/api/v1/dnsproxy"
)

var _ fqdnproxy.DNSProxier = &RemoteFQDNProxy{}

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "fqdnha/remoteproxy")
var fqdnRulesControllerGroup = controller.NewGroup("fqdn-rules")

const (
	fqdnRulesCacheController string        = "fqdn-rules-cache-controller"
	fqdnRulesUpdateTimeout   time.Duration = 10 * time.Second
	fqdnRulesCacheKeysSize   int           = 16
)

// RemoteFQDNProxy is a gRPC client used to communicate with the external
// fqdn-proxy.
// It handles FQDN rules updates and send them to the remote fqdn-proxy
// via a gRPC connection. The updates are identified by their fqdnRuleKey key,
// which is also used to deduplicate them. This is done to reduce the gRPC
// calls from the proxy plugin to the external fqdn-proxy and to guarantee
// that the latest update version will be sent to the fqdn-proxy.
type RemoteFQDNProxy struct {
	client     fqdnpb.FQDNProxyClient
	connection *grpc.ClientConn
	clientLock lock.Mutex

	controllers *controller.Manager
	done        chan struct{}

	// To keep the insertion O(1) and preserve updates ordering,
	// we use both a slice and a map. The slice is responsible for
	// storing the update keys preserving the order in which they
	// arrive, while the map will associate each key to its update.
	fqdnRulesCacheKeys []fqdnRuleKey
	fqdnRulesCacheMap  map[fqdnRuleKey]*fqdnpb.FQDNRules
	fqdnRulesCacheLock lock.Mutex
}

// fqdnRuleKey is a helper structure to be used as a key to
// identify messages in the update allowed messages cache.
// The endpoint ID and the destination port are sufficient to
// uniquely identify each update without generating string based
// hashes that may lead to excessive memory pressure.
type fqdnRuleKey struct {
	endpointID uint64
	destPort   uint32
}

func msgKey(msg *fqdnpb.FQDNRules) fqdnRuleKey {
	return fqdnRuleKey{msg.EndpointID, msg.DestPort}
}

func newRemoteFQDNProxy() *RemoteFQDNProxy {
	proxy := &RemoteFQDNProxy{
		controllers: controller.NewManager(),
		done:        make(chan struct{}),
	}
	proxy.resetCache()
	return proxy
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

func (r *RemoteFQDNProxy) Start(ctx cell.HookContext) error {
	// TODO: move this to a controller?
	go func() {
		r.resetClient()

		timer, done := inctimer.New()
		defer done()
		for {
			r.connection.WaitForStateChange(context.Background(), connectivity.Ready)
			r.resetClient()
			select {
			case <-r.done:
				return
			case <-timer.After(30 * time.Second):
				continue
			}
		}
	}()
	log.Info("FQDN HA proxy started")
	return nil
}

func (r *RemoteFQDNProxy) Stop(ctx cell.HookContext) error {
	close(r.done)
	log.Info("FQDN HA proxy stopped")
	return nil
}

func (r *RemoteFQDNProxy) GetRules(endpointID uint16) (restore.DNSRules, error) {
	rules, err := r.client.GetRules(context.TODO(), &fqdnpb.EndpointID{EndpointID: uint32(endpointID)})

	if err != nil {
		log.WithField(logfields.EndpointID, endpointID).WithError(err).Error("Failed to retrieve DNS rules from proxy")
		return nil, err
	}

	result := rulesFromProtobufMsg(rules)
	return result, nil
}

func (r *RemoteFQDNProxy) RemoveRestoredRules(endpointID uint16) {
	r.client.RemoveRestoredRules(context.TODO(), &fqdnpb.EndpointID{EndpointID: uint32(endpointID)})
}

func (r *RemoteFQDNProxy) UpdateAllowed(endpointID uint64, destPort restore.PortProto, newRules policy.L7DataMap) error {
	msg := &fqdnpb.FQDNRules{
		EndpointID: endpointID,
		DestPort:   uint32(destPort.Port()),
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

	r.enqueueFQDNRulesUpdate(msg)
	r.controllers.UpdateController(
		fqdnRulesCacheController,
		controller.ControllerParams{
			Group: fqdnRulesControllerGroup,
			DoFunc: func(ctx context.Context) error {
				return r.forwardFQDNRulesUpdates(ctx)
			},
		},
	)

	return nil
}

func (r *RemoteFQDNProxy) resetCache() {
	r.fqdnRulesCacheKeys = make([]fqdnRuleKey, 0, fqdnRulesCacheKeysSize)
	r.fqdnRulesCacheMap = make(map[fqdnRuleKey]*fqdnpb.FQDNRules)
}

func (r *RemoteFQDNProxy) enqueueFQDNRulesUpdate(msg *fqdnpb.FQDNRules) {
	r.fqdnRulesCacheLock.Lock()
	defer r.fqdnRulesCacheLock.Unlock()

	key := msgKey(msg)
	if _, ok := r.fqdnRulesCacheMap[key]; !ok {
		r.fqdnRulesCacheKeys = append(r.fqdnRulesCacheKeys, key)
	}
	// overwrite stale updates with the same fqdn rules message key
	r.fqdnRulesCacheMap[key] = msg
}

func (r *RemoteFQDNProxy) forwardFQDNRulesUpdates(ctx context.Context) error {
	r.fqdnRulesCacheLock.Lock()
	defer r.fqdnRulesCacheLock.Unlock()

	for len(r.fqdnRulesCacheKeys) > 0 {
		ctx, cancel := context.WithTimeout(ctx, fqdnRulesUpdateTimeout)
		defer cancel()

		key := r.fqdnRulesCacheKeys[0]
		msg := r.fqdnRulesCacheMap[key]
		if _, err := r.client.UpdateAllowed(ctx, msg); err != nil {
			log.WithFields(logrus.Fields{
				"newRules":           msg.Rules,
				logfields.EndpointID: msg.EndpointID,
			}).WithError(err).Error("Failed to forward FQDN rules update to remote proxy")
			return err
		}
		r.fqdnRulesCacheKeys = r.fqdnRulesCacheKeys[1:]
		delete(r.fqdnRulesCacheMap, key)
	}

	// release memory associated to both the slice and the map
	r.resetCache()

	return nil
}

func (r *RemoteFQDNProxy) Cleanup() {
	r.controllers.RemoveAllAndWait()
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

// Must be called with clientLock held
func (r *RemoteFQDNProxy) resetClient() {
	r.clientLock.Lock()
	defer r.clientLock.Unlock()

	if r.connection != nil {
		err := r.connection.Close()
		if err != nil {
			log.Errorf("Failed to close proxy connection: %v", err)
		}
	}
	var err error
	r.connection, err = grpc.Dial("unix:///var/run/cilium/proxy.sock", grpc.WithInsecure())
	if err != nil {
		log.Errorf("did not connect to proxy: %v", err)
	}
	r.client = fqdnpb.NewFQDNProxyClient(r.connection)
}

func rulesFromProtobufMsg(rules *fqdnpb.RestoredRules) restore.DNSRules {
	result := restore.DNSRules{}
	for port, msgIpRules := range rules.Rules {
		ipRules := make(restore.IPRules, 0, len(msgIpRules.List))

		for _, msgIpRule := range msgIpRules.List {
			ipRule := restore.IPRule{
				Re: restore.RuleRegex{
					Pattern: &msgIpRule.Regex,
				},
				IPs: make(map[string]struct{}, len(msgIpRule.Ips)),
			}

			for _, ip := range msgIpRule.Ips {
				ipRule.IPs[ip] = struct{}{}
			}

			ipRules = append(ipRules, ipRule)
		}

		result[(restore.PortProto)(port)] = ipRules
	}
	return result
}
