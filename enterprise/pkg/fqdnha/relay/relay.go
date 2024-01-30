// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/cilium/dns"
	"google.golang.org/grpc"

	pb "github.com/isovalent/fqdn-proxy/api/v1/dnsproxy"

	"github.com/cilium/cilium/daemon/cmd"
	fqdnhaconfig "github.com/cilium/cilium/enterprise/pkg/fqdnha/config"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha/doubleproxy"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/time"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "fqdnha/relay")

type FQDNProxyAgentServer struct {
	pb.UnimplementedFQDNProxyAgentServer

	grpcServer *grpc.Server

	daemonPromise   promise.Promise[*cmd.Daemon]
	restorerPromise promise.Promise[endpointstate.Restorer]

	dataSource      DNSProxyDataSource
	ipCacheGetter   IPCacheGetter
	endpointManager endpointmanager.EndpointManager
}

type params struct {
	cell.In

	DaemonPromise   promise.Promise[*cmd.Daemon]
	RestorerPromise promise.Promise[endpointstate.Restorer]
	IPCacheGetter   IPCacheGetter
	EndpointManager endpointmanager.EndpointManager
	Cfg             fqdnhaconfig.Config
}

func (s *FQDNProxyAgentServer) ProvideMappings(stream pb.FQDNProxyAgent_ProvideMappingsServer) error {
	for {
		mapping, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Success{
				Result: true,
			})
		}
		if err != nil {
			return err
		}

		addr := net.IP(mapping.IP)
		log.Debugf("%s -> %s", mapping.FQDN, addr.String())
	}
}

func (s *FQDNProxyAgentServer) LookupEndpointByIP(ctx context.Context, IP *pb.FQDN_IP) (*pb.Endpoint, error) {
	ip, ok := netip.AddrFromSlice(IP.IP)
	if !ok {
		return &pb.Endpoint{}, fmt.Errorf("unable to convert byte slice %v to netip.Addr", IP.IP)
	}
	ip = ip.Unmap()
	ep := s.endpointManager.LookupIP(ip)
	if ep == nil {
		return &pb.Endpoint{}, fmt.Errorf("cannot find endpoint with IP %s", ip)
	}

	return &pb.Endpoint{
		ID:        uint32(ep.ID),
		Identity:  uint32(ep.SecurityIdentity.ID),
		Namespace: ep.K8sNamespace,
		PodName:   ep.K8sPodName,
	}, nil
}

func (s *FQDNProxyAgentServer) LookupSecurityIdentityByIP(ctx context.Context, IP *pb.FQDN_IP) (*pb.Identity, error) {
	ip, ok := netip.AddrFromSlice(IP.IP)
	if !ok {
		return &pb.Identity{}, fmt.Errorf("unable to convert byte slice %v to netip.Addr", IP.IP)
	}
	id, exists := s.ipCacheGetter.LookupSecIDByIP(ip)
	return &pb.Identity{
		ID:     uint32(id.ID),
		Source: string(id.Source),
		Exists: exists,
	}, nil
}

func (s *FQDNProxyAgentServer) LookupIPsBySecurityIdentity(ctx context.Context, id *pb.Identity) (*pb.IPs, error) {
	ips := s.ipCacheGetter.LookupByIdentity(identity.NumericIdentity(id.ID))

	//TODO: should this not go to string and back to bytes for transfer?
	ipsForTransfer := make([][]byte, len(ips))

	for i, ip := range ips {
		ipsForTransfer[i] = []byte(net.ParseIP(ip))
	}

	return &pb.IPs{
		IPs: ipsForTransfer,
	}, nil
}

func (s *FQDNProxyAgentServer) NotifyOnDNSMessage(ctx context.Context, notification *pb.DNSNotification) (*pb.Empty, error) {
	//TODO: this should probably be factored out into stream of DNS notifications instead of a rpc call per DNS msg

	endpoint, err := s.endpointManager.Lookup(strconv.Itoa(int(notification.Endpoint.ID)))
	if err != nil {
		log.WithField("Endpoint ID", notification.Endpoint.ID).Errorf("Failed to retrieve endpoint")
	}

	dnsMsg := &dns.Msg{}
	err = dnsMsg.Unpack(notification.Msg)

	if err != nil {
		log.Errorf("Failed to unpack DNS message: %s", err)
		return &pb.Empty{}, err
	}

	return &pb.Empty{}, s.dataSource.NotifyOnDNSMsg(
		notification.Time.AsTime(),
		endpoint,
		notification.EpIPPort,
		identity.NumericIdentity(notification.ServerID),
		notification.ServerAddr,
		dnsMsg,
		notification.Protocol,
		notification.Allowed,
		nil)
}

func (s *FQDNProxyAgentServer) GetAllRules(ctx context.Context, empty *pb.Empty) (*pb.RestoredRulesMap, error) {
	double, ok := proxy.DefaultDNSProxy.(*doubleproxy.DoubleProxy)
	if !ok {
		return nil, nil
	}
	local, ok := double.LocalProxy.(*dnsproxy.DNSProxy)
	if !ok {
		return nil, fmt.Errorf("local proxy is not local")
	}
	allRules, err := local.GetAllRules()
	if err != nil {
		return nil, err
	}

	wholeMsg := &pb.RestoredRulesMap{Rules: make(map[uint64]*pb.RestoredRules, len(allRules))}
	for endpointID, rules := range allRules {
		msg := &pb.RestoredRules{Rules: make(map[uint32]*pb.IPRules, len(rules))}

		for port, ipRules := range rules {
			msgRules := &pb.IPRules{
				List: make([]*pb.IPRule, 0, len(ipRules)),
			}
			for _, ipRule := range ipRules {
				var pattern string
				if ipRule.Re.Pattern != nil {
					pattern = *ipRule.Re.Pattern
				}
				msgRule := &pb.IPRule{
					Regex: pattern,
					Ips:   make([]string, 0, len(ipRule.IPs)),
				}
				for ip := range ipRule.IPs {
					msgRule.Ips = append(msgRule.Ips, ip)
				}

				msgRules.List = append(msgRules.List, msgRule)
			}

			msg.Rules[uint32(port)] = msgRules
		}
		wholeMsg.Rules[endpointID] = msg
	}
	return wholeMsg, nil
}

func NewFQDNProxyAgentServer(
	lc hive.Lifecycle,
	p params,
) *FQDNProxyAgentServer {
	if !p.Cfg.EnableExternalDNSProxy {
		return nil
	}
	s := &FQDNProxyAgentServer{
		daemonPromise:   p.DaemonPromise,
		restorerPromise: p.RestorerPromise,
		ipCacheGetter:   p.IPCacheGetter,
		endpointManager: p.EndpointManager,
	}
	lc.Append(s)
	return s
}

func (s *FQDNProxyAgentServer) Start(ctx hive.HookContext) error {
	daemon, err := s.daemonPromise.Await(ctx)
	if err != nil {
		return err
	}
	s.dataSource = daemon

	restorer, err := s.restorerPromise.Await(ctx)
	if err != nil {
		return err
	}
	restorer.WaitForEndpointRestore(ctx)

	socket := "/var/run/cilium/proxy-agent.sock"
	os.Remove(socket)
	lis, err := net.Listen("unix", socket)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
		return err
	}
	var opts []grpc.ServerOption
	s.grpcServer = grpc.NewServer(opts...)
	pb.RegisterFQDNProxyAgentServer(s.grpcServer, s)

	log.Info("Starting FQDN relay gRPC server")
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			log.WithError(err).Error("Cannot start FQDN relay gRPC server")
		}
	}()
	return nil
}

func (s *FQDNProxyAgentServer) Stop(ctx hive.HookContext) error {
	log.Info("Stopping FQDN relay gRPC server")
	s.grpcServer.Stop()
	return nil
}

type DNSProxyDataSource interface {
	NotifyOnDNSMsg(time.Time, *endpoint.Endpoint, string, identity.NumericIdentity, string, *dns.Msg, string, bool, *dnsproxy.ProxyRequestContext) error
}

type IPCacheGetter interface {
	LookupByIdentity(identity.NumericIdentity) []string
	LookupSecIDByIP(netip.Addr) (ipcache.Identity, bool)
}
