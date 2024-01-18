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

	"github.com/cilium/cilium/enterprise/pkg/fqdnha/doubleproxy"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "fqdnha/relay")

type FQDNProxyAgentServer struct {
	pb.UnimplementedFQDNProxyAgentServer

	dataSource DNSProxyDataSource
	ipGetter   IPGetter
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
	ep, err := s.dataSource.LookupEPByIP(ip.Unmap())
	if err != nil {
		return &pb.Endpoint{}, err
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
	id, exists := s.ipGetter.LookupSecIDByIP(ip)

	return &pb.Identity{
		ID:     uint32(id.ID),
		Source: string(id.Source),
		Exists: exists,
	}, nil
}

func (s *FQDNProxyAgentServer) LookupIPsBySecurityIdentity(ctx context.Context, id *pb.Identity) (*pb.IPs, error) {
	ips := s.dataSource.LookupIPsBySecID(identity.NumericIdentity(id.ID))

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

	endpoint, err := s.dataSource.LookupEP(strconv.Itoa(int(notification.Endpoint.ID)))
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

func newServer(lookupSrc DNSProxyDataSource, ipGetter IPGetter) *FQDNProxyAgentServer {
	return &FQDNProxyAgentServer{
		dataSource: lookupSrc,
		ipGetter:   ipGetter,
	}
}

func RunServer(lookupSrc DNSProxyDataSource, ipGetter IPGetter, stat *spanstat.SpanStat) error {
	if stat != nil {
		stat.Start()
	}

	socket := "/var/run/cilium/proxy-agent.sock"
	os.Remove(socket)
	lis, err := net.Listen("unix", socket)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterFQDNProxyAgentServer(grpcServer, newServer(lookupSrc, ipGetter))

	if stat != nil {
		stat.End(true)
	}

	log.Info("Starting FQDN relay gRPC server")

	return grpcServer.Serve(lis)
}

type DNSProxyDataSource interface {
	LookupEPByIP(netip.Addr) (*endpoint.Endpoint, error)
	LookupIPsBySecID(identity.NumericIdentity) []string
	NotifyOnDNSMsg(time.Time, *endpoint.Endpoint, string, identity.NumericIdentity, string, *dns.Msg, string, bool, *dnsproxy.ProxyRequestContext) error
	LookupEP(string) (*endpoint.Endpoint, error)
}

type IPGetter interface {
	LookupSecIDByIP(netip.Addr) (ipcache.Identity, bool)
}
