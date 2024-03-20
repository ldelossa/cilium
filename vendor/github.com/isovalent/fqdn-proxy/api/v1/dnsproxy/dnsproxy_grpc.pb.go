// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package dnsproxy

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// FQDNProxyAgentClient is the client API for FQDNProxyAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type FQDNProxyAgentClient interface {
	// A client-to-server streaming RPC.
	//
	// Accepts a stream of FQDNMapping
	ProvideMappings(ctx context.Context, opts ...grpc.CallOption) (FQDNProxyAgent_ProvideMappingsClient, error)
	// LookupEndpointByIP returns endpoint data based on IP
	LookupEndpointByIP(ctx context.Context, in *FQDN_IP, opts ...grpc.CallOption) (*Endpoint, error)
	// LookupEndpointByIP returns endpoint data based on IP
	LookupSecurityIdentityByIP(ctx context.Context, in *FQDN_IP, opts ...grpc.CallOption) (*Identity, error)
	// LookupIPsBySecurityIdentity retrieves ips for endpoints with given security identity
	LookupIPsBySecurityIdentity(ctx context.Context, in *Identity, opts ...grpc.CallOption) (*IPs, error)
	// NotifyOnDNSMessage notifies Agent of a DNS message
	NotifyOnDNSMessage(ctx context.Context, in *DNSNotification, opts ...grpc.CallOption) (*Empty, error)
	// GetAllRules retrieves all FQDN rules from agent proxy
	GetAllRules(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*RestoredRulesMap, error)
}

type fQDNProxyAgentClient struct {
	cc grpc.ClientConnInterface
}

func NewFQDNProxyAgentClient(cc grpc.ClientConnInterface) FQDNProxyAgentClient {
	return &fQDNProxyAgentClient{cc}
}

func (c *fQDNProxyAgentClient) ProvideMappings(ctx context.Context, opts ...grpc.CallOption) (FQDNProxyAgent_ProvideMappingsClient, error) {
	stream, err := c.cc.NewStream(ctx, &_FQDNProxyAgent_serviceDesc.Streams[0], "/dnsproxy.FQDNProxyAgent/ProvideMappings", opts...)
	if err != nil {
		return nil, err
	}
	x := &fQDNProxyAgentProvideMappingsClient{stream}
	return x, nil
}

type FQDNProxyAgent_ProvideMappingsClient interface {
	Send(*FQDNMapping) error
	CloseAndRecv() (*Success, error)
	grpc.ClientStream
}

type fQDNProxyAgentProvideMappingsClient struct {
	grpc.ClientStream
}

func (x *fQDNProxyAgentProvideMappingsClient) Send(m *FQDNMapping) error {
	return x.ClientStream.SendMsg(m)
}

func (x *fQDNProxyAgentProvideMappingsClient) CloseAndRecv() (*Success, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(Success)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *fQDNProxyAgentClient) LookupEndpointByIP(ctx context.Context, in *FQDN_IP, opts ...grpc.CallOption) (*Endpoint, error) {
	out := new(Endpoint)
	err := c.cc.Invoke(ctx, "/dnsproxy.FQDNProxyAgent/LookupEndpointByIP", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fQDNProxyAgentClient) LookupSecurityIdentityByIP(ctx context.Context, in *FQDN_IP, opts ...grpc.CallOption) (*Identity, error) {
	out := new(Identity)
	err := c.cc.Invoke(ctx, "/dnsproxy.FQDNProxyAgent/LookupSecurityIdentityByIP", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fQDNProxyAgentClient) LookupIPsBySecurityIdentity(ctx context.Context, in *Identity, opts ...grpc.CallOption) (*IPs, error) {
	out := new(IPs)
	err := c.cc.Invoke(ctx, "/dnsproxy.FQDNProxyAgent/LookupIPsBySecurityIdentity", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fQDNProxyAgentClient) NotifyOnDNSMessage(ctx context.Context, in *DNSNotification, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, "/dnsproxy.FQDNProxyAgent/NotifyOnDNSMessage", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fQDNProxyAgentClient) GetAllRules(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*RestoredRulesMap, error) {
	out := new(RestoredRulesMap)
	err := c.cc.Invoke(ctx, "/dnsproxy.FQDNProxyAgent/GetAllRules", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FQDNProxyAgentServer is the server API for FQDNProxyAgent service.
// All implementations should embed UnimplementedFQDNProxyAgentServer
// for forward compatibility
type FQDNProxyAgentServer interface {
	// A client-to-server streaming RPC.
	//
	// Accepts a stream of FQDNMapping
	ProvideMappings(FQDNProxyAgent_ProvideMappingsServer) error
	// LookupEndpointByIP returns endpoint data based on IP
	LookupEndpointByIP(context.Context, *FQDN_IP) (*Endpoint, error)
	// LookupEndpointByIP returns endpoint data based on IP
	LookupSecurityIdentityByIP(context.Context, *FQDN_IP) (*Identity, error)
	// LookupIPsBySecurityIdentity retrieves ips for endpoints with given security identity
	LookupIPsBySecurityIdentity(context.Context, *Identity) (*IPs, error)
	// NotifyOnDNSMessage notifies Agent of a DNS message
	NotifyOnDNSMessage(context.Context, *DNSNotification) (*Empty, error)
	// GetAllRules retrieves all FQDN rules from agent proxy
	GetAllRules(context.Context, *Empty) (*RestoredRulesMap, error)
}

// UnimplementedFQDNProxyAgentServer should be embedded to have forward compatible implementations.
type UnimplementedFQDNProxyAgentServer struct {
}

func (*UnimplementedFQDNProxyAgentServer) ProvideMappings(FQDNProxyAgent_ProvideMappingsServer) error {
	return status.Errorf(codes.Unimplemented, "method ProvideMappings not implemented")
}
func (*UnimplementedFQDNProxyAgentServer) LookupEndpointByIP(context.Context, *FQDN_IP) (*Endpoint, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LookupEndpointByIP not implemented")
}
func (*UnimplementedFQDNProxyAgentServer) LookupSecurityIdentityByIP(context.Context, *FQDN_IP) (*Identity, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LookupSecurityIdentityByIP not implemented")
}
func (*UnimplementedFQDNProxyAgentServer) LookupIPsBySecurityIdentity(context.Context, *Identity) (*IPs, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LookupIPsBySecurityIdentity not implemented")
}
func (*UnimplementedFQDNProxyAgentServer) NotifyOnDNSMessage(context.Context, *DNSNotification) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method NotifyOnDNSMessage not implemented")
}
func (*UnimplementedFQDNProxyAgentServer) GetAllRules(context.Context, *Empty) (*RestoredRulesMap, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAllRules not implemented")
}

func RegisterFQDNProxyAgentServer(s *grpc.Server, srv FQDNProxyAgentServer) {
	s.RegisterService(&_FQDNProxyAgent_serviceDesc, srv)
}

func _FQDNProxyAgent_ProvideMappings_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(FQDNProxyAgentServer).ProvideMappings(&fQDNProxyAgentProvideMappingsServer{stream})
}

type FQDNProxyAgent_ProvideMappingsServer interface {
	SendAndClose(*Success) error
	Recv() (*FQDNMapping, error)
	grpc.ServerStream
}

type fQDNProxyAgentProvideMappingsServer struct {
	grpc.ServerStream
}

func (x *fQDNProxyAgentProvideMappingsServer) SendAndClose(m *Success) error {
	return x.ServerStream.SendMsg(m)
}

func (x *fQDNProxyAgentProvideMappingsServer) Recv() (*FQDNMapping, error) {
	m := new(FQDNMapping)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _FQDNProxyAgent_LookupEndpointByIP_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FQDN_IP)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FQDNProxyAgentServer).LookupEndpointByIP(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dnsproxy.FQDNProxyAgent/LookupEndpointByIP",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FQDNProxyAgentServer).LookupEndpointByIP(ctx, req.(*FQDN_IP))
	}
	return interceptor(ctx, in, info, handler)
}

func _FQDNProxyAgent_LookupSecurityIdentityByIP_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FQDN_IP)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FQDNProxyAgentServer).LookupSecurityIdentityByIP(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dnsproxy.FQDNProxyAgent/LookupSecurityIdentityByIP",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FQDNProxyAgentServer).LookupSecurityIdentityByIP(ctx, req.(*FQDN_IP))
	}
	return interceptor(ctx, in, info, handler)
}

func _FQDNProxyAgent_LookupIPsBySecurityIdentity_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Identity)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FQDNProxyAgentServer).LookupIPsBySecurityIdentity(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dnsproxy.FQDNProxyAgent/LookupIPsBySecurityIdentity",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FQDNProxyAgentServer).LookupIPsBySecurityIdentity(ctx, req.(*Identity))
	}
	return interceptor(ctx, in, info, handler)
}

func _FQDNProxyAgent_NotifyOnDNSMessage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DNSNotification)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FQDNProxyAgentServer).NotifyOnDNSMessage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dnsproxy.FQDNProxyAgent/NotifyOnDNSMessage",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FQDNProxyAgentServer).NotifyOnDNSMessage(ctx, req.(*DNSNotification))
	}
	return interceptor(ctx, in, info, handler)
}

func _FQDNProxyAgent_GetAllRules_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FQDNProxyAgentServer).GetAllRules(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dnsproxy.FQDNProxyAgent/GetAllRules",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FQDNProxyAgentServer).GetAllRules(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

var _FQDNProxyAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "dnsproxy.FQDNProxyAgent",
	HandlerType: (*FQDNProxyAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "LookupEndpointByIP",
			Handler:    _FQDNProxyAgent_LookupEndpointByIP_Handler,
		},
		{
			MethodName: "LookupSecurityIdentityByIP",
			Handler:    _FQDNProxyAgent_LookupSecurityIdentityByIP_Handler,
		},
		{
			MethodName: "LookupIPsBySecurityIdentity",
			Handler:    _FQDNProxyAgent_LookupIPsBySecurityIdentity_Handler,
		},
		{
			MethodName: "NotifyOnDNSMessage",
			Handler:    _FQDNProxyAgent_NotifyOnDNSMessage_Handler,
		},
		{
			MethodName: "GetAllRules",
			Handler:    _FQDNProxyAgent_GetAllRules_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ProvideMappings",
			Handler:       _FQDNProxyAgent_ProvideMappings_Handler,
			ClientStreams: true,
		},
	},
	Metadata: "dnsproxy/dnsproxy.proto",
}

// FQDNProxyClient is the client API for FQDNProxy service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type FQDNProxyClient interface {
	UpdateAllowed(ctx context.Context, in *FQDNRules, opts ...grpc.CallOption) (*Empty, error)
	RemoveRestoredRules(ctx context.Context, in *EndpointID, opts ...grpc.CallOption) (*Empty, error)
	GetRules(ctx context.Context, in *EndpointID, opts ...grpc.CallOption) (*RestoredRules, error)
}

type fQDNProxyClient struct {
	cc grpc.ClientConnInterface
}

func NewFQDNProxyClient(cc grpc.ClientConnInterface) FQDNProxyClient {
	return &fQDNProxyClient{cc}
}

func (c *fQDNProxyClient) UpdateAllowed(ctx context.Context, in *FQDNRules, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, "/dnsproxy.FQDNProxy/UpdateAllowed", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fQDNProxyClient) RemoveRestoredRules(ctx context.Context, in *EndpointID, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, "/dnsproxy.FQDNProxy/RemoveRestoredRules", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *fQDNProxyClient) GetRules(ctx context.Context, in *EndpointID, opts ...grpc.CallOption) (*RestoredRules, error) {
	out := new(RestoredRules)
	err := c.cc.Invoke(ctx, "/dnsproxy.FQDNProxy/GetRules", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FQDNProxyServer is the server API for FQDNProxy service.
// All implementations should embed UnimplementedFQDNProxyServer
// for forward compatibility
type FQDNProxyServer interface {
	UpdateAllowed(context.Context, *FQDNRules) (*Empty, error)
	RemoveRestoredRules(context.Context, *EndpointID) (*Empty, error)
	GetRules(context.Context, *EndpointID) (*RestoredRules, error)
}

// UnimplementedFQDNProxyServer should be embedded to have forward compatible implementations.
type UnimplementedFQDNProxyServer struct {
}

func (*UnimplementedFQDNProxyServer) UpdateAllowed(context.Context, *FQDNRules) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAllowed not implemented")
}
func (*UnimplementedFQDNProxyServer) RemoveRestoredRules(context.Context, *EndpointID) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveRestoredRules not implemented")
}
func (*UnimplementedFQDNProxyServer) GetRules(context.Context, *EndpointID) (*RestoredRules, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetRules not implemented")
}

func RegisterFQDNProxyServer(s *grpc.Server, srv FQDNProxyServer) {
	s.RegisterService(&_FQDNProxy_serviceDesc, srv)
}

func _FQDNProxy_UpdateAllowed_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FQDNRules)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FQDNProxyServer).UpdateAllowed(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dnsproxy.FQDNProxy/UpdateAllowed",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FQDNProxyServer).UpdateAllowed(ctx, req.(*FQDNRules))
	}
	return interceptor(ctx, in, info, handler)
}

func _FQDNProxy_RemoveRestoredRules_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EndpointID)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FQDNProxyServer).RemoveRestoredRules(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dnsproxy.FQDNProxy/RemoveRestoredRules",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FQDNProxyServer).RemoveRestoredRules(ctx, req.(*EndpointID))
	}
	return interceptor(ctx, in, info, handler)
}

func _FQDNProxy_GetRules_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EndpointID)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FQDNProxyServer).GetRules(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/dnsproxy.FQDNProxy/GetRules",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FQDNProxyServer).GetRules(ctx, req.(*EndpointID))
	}
	return interceptor(ctx, in, info, handler)
}

var _FQDNProxy_serviceDesc = grpc.ServiceDesc{
	ServiceName: "dnsproxy.FQDNProxy",
	HandlerType: (*FQDNProxyServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "UpdateAllowed",
			Handler:    _FQDNProxy_UpdateAllowed_Handler,
		},
		{
			MethodName: "RemoveRestoredRules",
			Handler:    _FQDNProxy_RemoveRestoredRules_Handler,
		},
		{
			MethodName: "GetRules",
			Handler:    _FQDNProxy_GetRules_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "dnsproxy/dnsproxy.proto",
}