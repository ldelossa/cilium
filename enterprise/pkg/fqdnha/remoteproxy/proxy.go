// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remoteproxy

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/cilium/hive/cell"

	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
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
	endpointID    uint64
	destPortProto uint32
}

func msgKey(msg *fqdnpb.FQDNRules) fqdnRuleKey {
	pp := restore.PortProto(msg.DestPort)
	if msg.DestProto != 0 {
		pp = restore.MakeV2PortProto(uint16(msg.DestPort), uint8(msg.DestProto))
	}
	return fqdnRuleKey{msg.EndpointID, uint32(pp)}
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

func (r *RemoteFQDNProxy) Start(_ cell.HookContext) error {
	var connection *grpc.ClientConn
	var logOnce sync.Once
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-r.done
			cancel()
		}()

		timer, done := inctimer.New()
		defer done()
		for {
			// a connection already exists
			if connection != nil {
				err := connection.Close()
				if err != nil {
					// Close() fails only if we try to close multiple times
					log.WithError(err).Error("Failed to close proxy connection")
				}
			}

			// create a new connection
			var err error
			connection, err = grpc.DialContext(ctx, "unix:///var/run/cilium/proxy.sock", grpc.WithInsecure())
			if err != nil {
				log.WithError(err).Error("Failed to dial remote proxy server")
			} else {
				r.clientLock.Lock()
				r.client = fqdnpb.NewFQDNProxyClient(connection)
				r.clientLock.Unlock()

				logOnce.Do(func() {
					log.Info("FQDN HA proxy started")
				})

				// Block while connection is ready
				connection.WaitForStateChange(ctx, connectivity.Ready)
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

func (r *RemoteFQDNProxy) getClient() (fqdnpb.FQDNProxyClient, error) {
	r.clientLock.Lock()
	defer r.clientLock.Unlock()
	if r.client == nil {
		return nil, errors.New("remote FQDN proxy is not initialized")
	}
	return r.client, nil
}

func (r *RemoteFQDNProxy) Stop(ctx cell.HookContext) error {
	close(r.done)
	log.Info("FQDN HA proxy stopped")
	return nil
}

func (r *RemoteFQDNProxy) GetRules(endpointID uint16) (restore.DNSRules, error) {
	client, err := r.getClient()
	if err != nil {
		return nil, fmt.Errorf("RemoveRestoredRules called before proxy was initialized: %w", err)
	}

	rules, err := client.GetRules(context.TODO(), &fqdnpb.EndpointID{EndpointID: uint32(endpointID)})

	if err != nil {
		log.WithField(logfields.EndpointID, endpointID).WithError(err).Error("Failed to retrieve DNS rules from proxy")
		return nil, err
	}

	result := rulesFromProtobufMsg(rules)
	return result, nil
}

func (r *RemoteFQDNProxy) RemoveRestoredRules(endpointID uint16) {
	client, err := r.getClient()
	if err != nil {
		log.Error("RemoveRestoredRules called before proxy was initialized")
		return
	}
	client.RemoveRestoredRules(context.TODO(), &fqdnpb.EndpointID{EndpointID: uint32(endpointID)})
}

func (r *RemoteFQDNProxy) UpdateAllowed(endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) error {
	// Filter out protocols that cannot apply to DNS.
	if proto := destPortProto.Protocol(); proto != uint8(u8proto.UDP) && proto != uint8(u8proto.TCP) {
		return nil
	}
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

	client, err := r.getClient()
	if err != nil {
		return errors.New("failed to forward FQDN rules update to remote proxy because remote proxy is not running")
	}

	for len(r.fqdnRulesCacheKeys) > 0 {
		ctx, cancel := context.WithTimeout(ctx, fqdnRulesUpdateTimeout)
		defer cancel()

		key := r.fqdnRulesCacheKeys[0]
		msg := r.fqdnRulesCacheMap[key]

		if _, err := client.UpdateAllowed(ctx, msg); err != nil {
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

func rulesFromProtobufMsg(rules *fqdnpb.RestoredRules) restore.DNSRules {
	result := restore.DNSRules{}
	for portProto, msgIpRules := range rules.Rules {
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

		result[restore.PortProto(portProto)] = ipRules
	}
	return result
}
