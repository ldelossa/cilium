// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.22.3
// source: aggregation.proto

package aggregation

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type StateChange int32

const (
	// unspec represents no change in state
	StateChange_unspec StateChange = 0
	// new indicates that the flow has been observed for the first time,
	// e.g. for connection aggregation, the first time a 5-tuple + verdict
	// + drop-reason has been observed.
	StateChange_new StateChange = 1
	// established indicates that the connection handshake has been
	// successful, i.e. for TCP this means that the 3-way handshake has
	// been successful. For any non-TCP protocol, the first flow in any
	// direction triggers established state.
	StateChange_established StateChange = 2
	// first_error indicates that an error has been observed on the flow
	// for the first time
	StateChange_first_error StateChange = 4
	// error indicates that the latest flow reported an error condition.
	// For TCP, this indicates that an RST has been observed.  For HTTP,
	// this indicates that a 4xx or 5xx status code has been observed.
	StateChange_error StateChange = 8
	// closed indicates closure of the connection, e.g. a TCP FIN has been
	// seen in both direction. For non-TCP, this state is never triggered.
	// This state is never reached for non-connection aggregation.
	StateChange_closed StateChange = 16
	// first_reply indicates that a flow with is_reply set to true has been
	// observed on the flow for the first time.
	StateChange_first_reply StateChange = 32
)

// Enum value maps for StateChange.
var (
	StateChange_name = map[int32]string{
		0:  "unspec",
		1:  "new",
		2:  "established",
		4:  "first_error",
		8:  "error",
		16: "closed",
		32: "first_reply",
	}
	StateChange_value = map[string]int32{
		"unspec":      0,
		"new":         1,
		"established": 2,
		"first_error": 4,
		"error":       8,
		"closed":      16,
		"first_reply": 32,
	}
)

func (x StateChange) Enum() *StateChange {
	p := new(StateChange)
	*p = x
	return p
}

func (x StateChange) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (StateChange) Descriptor() protoreflect.EnumDescriptor {
	return file_aggregation_proto_enumTypes[0].Descriptor()
}

func (StateChange) Type() protoreflect.EnumType {
	return &file_aggregation_proto_enumTypes[0]
}

func (x StateChange) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use StateChange.Descriptor instead.
func (StateChange) EnumDescriptor() ([]byte, []int) {
	return file_aggregation_proto_rawDescGZIP(), []int{0}
}

// AggregatorType are all aggregator types
type AggregatorType int32

const (
	AggregatorType_unknown    AggregatorType = 0
	AggregatorType_connection AggregatorType = 1
	AggregatorType_identity   AggregatorType = 2
)

// Enum value maps for AggregatorType.
var (
	AggregatorType_name = map[int32]string{
		0: "unknown",
		1: "connection",
		2: "identity",
	}
	AggregatorType_value = map[string]int32{
		"unknown":    0,
		"connection": 1,
		"identity":   2,
	}
)

func (x AggregatorType) Enum() *AggregatorType {
	p := new(AggregatorType)
	*p = x
	return p
}

func (x AggregatorType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AggregatorType) Descriptor() protoreflect.EnumDescriptor {
	return file_aggregation_proto_enumTypes[1].Descriptor()
}

func (AggregatorType) Type() protoreflect.EnumType {
	return &file_aggregation_proto_enumTypes[1]
}

func (x AggregatorType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AggregatorType.Descriptor instead.
func (AggregatorType) EnumDescriptor() ([]byte, []int) {
	return file_aggregation_proto_rawDescGZIP(), []int{1}
}

// DirectionStatistics are flow statistics in a particular direction
type DirectionStatistics struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// first_activity is the timestamp of first activity on the flow
	FirstActivity *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=first_activity,json=firstActivity,proto3" json:"first_activity,omitempty"`
	// last_activity is the timestamp when activity was last observed
	LastActivity *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=last_activity,json=lastActivity,proto3" json:"last_activity,omitempty"`
	// num_flows is the number of flows aggregated together
	NumFlows uint64 `protobuf:"varint,3,opt,name=num_flows,json=numFlows,proto3" json:"num_flows,omitempty"`
	// bytes is the number of bytes observed on the flow
	Bytes uint64 `protobuf:"varint,4,opt,name=bytes,proto3" json:"bytes,omitempty"`
	// errors is the number of errors observed on the flow, e.g. RSTs or
	// HTTP 4xx 5xx status returns
	Errors uint64 `protobuf:"varint,5,opt,name=errors,proto3" json:"errors,omitempty"`
	// ack_seen is true once a TCP ACK has been seen in this direction
	AckSeen bool `protobuf:"varint,6,opt,name=ack_seen,json=ackSeen,proto3" json:"ack_seen,omitempty"`
	// connect_requests is the number of requests for new connections, i.e.
	// the number of SYNs seen
	ConnectionAttempts uint64 `protobuf:"varint,7,opt,name=connection_attempts,json=connectionAttempts,proto3" json:"connection_attempts,omitempty"`
	// close_requests is the number of connection closure requests
	// received, i.e. the number of FINs seen
	CloseRequests uint64 `protobuf:"varint,8,opt,name=close_requests,json=closeRequests,proto3" json:"close_requests,omitempty"`
}

func (x *DirectionStatistics) Reset() {
	*x = DirectionStatistics{}
	if protoimpl.UnsafeEnabled {
		mi := &file_aggregation_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DirectionStatistics) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DirectionStatistics) ProtoMessage() {}

func (x *DirectionStatistics) ProtoReflect() protoreflect.Message {
	mi := &file_aggregation_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DirectionStatistics.ProtoReflect.Descriptor instead.
func (*DirectionStatistics) Descriptor() ([]byte, []int) {
	return file_aggregation_proto_rawDescGZIP(), []int{0}
}

func (x *DirectionStatistics) GetFirstActivity() *timestamppb.Timestamp {
	if x != nil {
		return x.FirstActivity
	}
	return nil
}

func (x *DirectionStatistics) GetLastActivity() *timestamppb.Timestamp {
	if x != nil {
		return x.LastActivity
	}
	return nil
}

func (x *DirectionStatistics) GetNumFlows() uint64 {
	if x != nil {
		return x.NumFlows
	}
	return 0
}

func (x *DirectionStatistics) GetBytes() uint64 {
	if x != nil {
		return x.Bytes
	}
	return 0
}

func (x *DirectionStatistics) GetErrors() uint64 {
	if x != nil {
		return x.Errors
	}
	return 0
}

func (x *DirectionStatistics) GetAckSeen() bool {
	if x != nil {
		return x.AckSeen
	}
	return false
}

func (x *DirectionStatistics) GetConnectionAttempts() uint64 {
	if x != nil {
		return x.ConnectionAttempts
	}
	return 0
}

func (x *DirectionStatistics) GetCloseRequests() uint64 {
	if x != nil {
		return x.CloseRequests
	}
	return 0
}

// FlowStatistics includes the statistics for a flow in both directions
type FlowStatistics struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// forward represents flow statistics in the forward direction
	Forward *DirectionStatistics `protobuf:"bytes,1,opt,name=forward,proto3" json:"forward,omitempty"`
	// reply represents flow statistics in the reply direction
	Reply *DirectionStatistics `protobuf:"bytes,2,opt,name=reply,proto3" json:"reply,omitempty"`
	// established is set to true once the connection/flow is established
	Established bool `protobuf:"varint,3,opt,name=established,proto3" json:"established,omitempty"`
}

func (x *FlowStatistics) Reset() {
	*x = FlowStatistics{}
	if protoimpl.UnsafeEnabled {
		mi := &file_aggregation_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FlowStatistics) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FlowStatistics) ProtoMessage() {}

func (x *FlowStatistics) ProtoReflect() protoreflect.Message {
	mi := &file_aggregation_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FlowStatistics.ProtoReflect.Descriptor instead.
func (*FlowStatistics) Descriptor() ([]byte, []int) {
	return file_aggregation_proto_rawDescGZIP(), []int{1}
}

func (x *FlowStatistics) GetForward() *DirectionStatistics {
	if x != nil {
		return x.Forward
	}
	return nil
}

func (x *FlowStatistics) GetReply() *DirectionStatistics {
	if x != nil {
		return x.Reply
	}
	return nil
}

func (x *FlowStatistics) GetEstablished() bool {
	if x != nil {
		return x.Established
	}
	return false
}

// Aggregator is an aggregator configuration
type Aggregator struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type AggregatorType `protobuf:"varint,1,opt,name=type,proto3,enum=isovalent.flow.aggregation.AggregatorType" json:"type,omitempty"`
	// Ignore source port during aggregation.
	IgnoreSourcePort bool `protobuf:"varint,2,opt,name=ignore_source_port,json=ignoreSourcePort,proto3" json:"ignore_source_port,omitempty"`
	// Specify the flow TTL for this aggregator. Defaults to 30 seconds.
	Ttl *durationpb.Duration `protobuf:"bytes,3,opt,name=ttl,proto3" json:"ttl,omitempty"`
	// By default, the flow TTL gets renewed when there is an activity on a
	// given aggregation target (connection or identity). This means that flows
	// do not expire unless they remain inactive for the duration specified in
	// the ttl field. Set this flag to false to expire flows after their initial
	// TTLs regardless of whether there have been subsequent flows on their
	// aggregation targets.
	RenewTtl *wrapperspb.BoolValue `protobuf:"bytes,4,opt,name=renew_ttl,json=renewTtl,proto3" json:"renew_ttl,omitempty"`
}

func (x *Aggregator) Reset() {
	*x = Aggregator{}
	if protoimpl.UnsafeEnabled {
		mi := &file_aggregation_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Aggregator) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Aggregator) ProtoMessage() {}

func (x *Aggregator) ProtoReflect() protoreflect.Message {
	mi := &file_aggregation_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Aggregator.ProtoReflect.Descriptor instead.
func (*Aggregator) Descriptor() ([]byte, []int) {
	return file_aggregation_proto_rawDescGZIP(), []int{2}
}

func (x *Aggregator) GetType() AggregatorType {
	if x != nil {
		return x.Type
	}
	return AggregatorType_unknown
}

func (x *Aggregator) GetIgnoreSourcePort() bool {
	if x != nil {
		return x.IgnoreSourcePort
	}
	return false
}

func (x *Aggregator) GetTtl() *durationpb.Duration {
	if x != nil {
		return x.Ttl
	}
	return nil
}

func (x *Aggregator) GetRenewTtl() *wrapperspb.BoolValue {
	if x != nil {
		return x.RenewTtl
	}
	return nil
}

// Aggregation is a filter to define flow aggregation behavior
type Aggregation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// aggregators is a list of aggregators to apply on flows before
	// returning them. If multiple aggregator are defined, all of them are
	// applied in a row.
	Aggregators []*Aggregator `protobuf:"bytes,1,rep,name=aggregators,proto3" json:"aggregators,omitempty"`
	// state_change_filter lists the state changes to consider when
	// determing to return an updated flow while aggregating
	StateChangeFilter StateChange `protobuf:"varint,2,opt,name=state_change_filter,json=stateChangeFilter,proto3,enum=isovalent.flow.aggregation.StateChange" json:"state_change_filter,omitempty"`
}

func (x *Aggregation) Reset() {
	*x = Aggregation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_aggregation_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Aggregation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Aggregation) ProtoMessage() {}

func (x *Aggregation) ProtoReflect() protoreflect.Message {
	mi := &file_aggregation_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Aggregation.ProtoReflect.Descriptor instead.
func (*Aggregation) Descriptor() ([]byte, []int) {
	return file_aggregation_proto_rawDescGZIP(), []int{3}
}

func (x *Aggregation) GetAggregators() []*Aggregator {
	if x != nil {
		return x.Aggregators
	}
	return nil
}

func (x *Aggregation) GetStateChangeFilter() StateChange {
	if x != nil {
		return x.StateChangeFilter
	}
	return StateChange_unspec
}

var File_aggregation_proto protoreflect.FileDescriptor

var file_aggregation_proto_rawDesc = []byte{
	0x0a, 0x11, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x69, 0x73, 0x6f, 0x76, 0x61, 0x6c, 0x65, 0x6e, 0x74, 0x2e, 0x66,
	0x6c, 0x6f, 0x77, 0x2e, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x1a,
	0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xd7, 0x02, 0x0a, 0x13, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74,
	0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x12, 0x41, 0x0a, 0x0e, 0x66, 0x69, 0x72, 0x73,
	0x74, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0d, 0x66, 0x69,
	0x72, 0x73, 0x74, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x12, 0x3f, 0x0a, 0x0d, 0x6c,
	0x61, 0x73, 0x74, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0c,
	0x6c, 0x61, 0x73, 0x74, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x12, 0x1b, 0x0a, 0x09,
	0x6e, 0x75, 0x6d, 0x5f, 0x66, 0x6c, 0x6f, 0x77, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x08, 0x6e, 0x75, 0x6d, 0x46, 0x6c, 0x6f, 0x77, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x62, 0x79, 0x74,
	0x65, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x62, 0x79, 0x74, 0x65, 0x73, 0x12,
	0x16, 0x0a, 0x06, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x06, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x73, 0x12, 0x19, 0x0a, 0x08, 0x61, 0x63, 0x6b, 0x5f, 0x73,
	0x65, 0x65, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x61, 0x63, 0x6b, 0x53, 0x65,
	0x65, 0x6e, 0x12, 0x2f, 0x0a, 0x13, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x5f, 0x61, 0x74, 0x74, 0x65, 0x6d, 0x70, 0x74, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x12, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x74, 0x74, 0x65, 0x6d,
	0x70, 0x74, 0x73, 0x12, 0x25, 0x0a, 0x0e, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x5f, 0x72, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x73, 0x18, 0x08, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0d, 0x63, 0x6c, 0x6f,
	0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x22, 0xc4, 0x01, 0x0a, 0x0e, 0x46,
	0x6c, 0x6f, 0x77, 0x53, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x12, 0x49, 0x0a,
	0x07, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2f,
	0x2e, 0x69, 0x73, 0x6f, 0x76, 0x61, 0x6c, 0x65, 0x6e, 0x74, 0x2e, 0x66, 0x6c, 0x6f, 0x77, 0x2e,
	0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x44, 0x69, 0x72, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x52,
	0x07, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x12, 0x45, 0x0a, 0x05, 0x72, 0x65, 0x70, 0x6c,
	0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2f, 0x2e, 0x69, 0x73, 0x6f, 0x76, 0x61, 0x6c,
	0x65, 0x6e, 0x74, 0x2e, 0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74,
	0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73, 0x52, 0x05, 0x72, 0x65, 0x70, 0x6c, 0x79, 0x12,
	0x20, 0x0a, 0x0b, 0x65, 0x73, 0x74, 0x61, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65, 0x64, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x65, 0x73, 0x74, 0x61, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65,
	0x64, 0x22, 0xe0, 0x01, 0x0a, 0x0a, 0x41, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x6f, 0x72,
	0x12, 0x3e, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x2a,
	0x2e, 0x69, 0x73, 0x6f, 0x76, 0x61, 0x6c, 0x65, 0x6e, 0x74, 0x2e, 0x66, 0x6c, 0x6f, 0x77, 0x2e,
	0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x41, 0x67, 0x67, 0x72,
	0x65, 0x67, 0x61, 0x74, 0x6f, 0x72, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x12, 0x2c, 0x0a, 0x12, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x10, 0x69, 0x67,
	0x6e, 0x6f, 0x72, 0x65, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x2b,
	0x0a, 0x03, 0x74, 0x74, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x03, 0x74, 0x74, 0x6c, 0x12, 0x37, 0x0a, 0x09, 0x72,
	0x65, 0x6e, 0x65, 0x77, 0x5f, 0x74, 0x74, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x42, 0x6f, 0x6f, 0x6c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x08, 0x72, 0x65, 0x6e, 0x65,
	0x77, 0x54, 0x74, 0x6c, 0x22, 0xb0, 0x01, 0x0a, 0x0b, 0x41, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x48, 0x0a, 0x0b, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74,
	0x6f, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x69, 0x73, 0x6f, 0x76,
	0x61, 0x6c, 0x65, 0x6e, 0x74, 0x2e, 0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x61, 0x67, 0x67, 0x72, 0x65,
	0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x41, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x6f,
	0x72, 0x52, 0x0b, 0x61, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x6f, 0x72, 0x73, 0x12, 0x57,
	0x0a, 0x13, 0x73, 0x74, 0x61, 0x74, 0x65, 0x5f, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x5f, 0x66,
	0x69, 0x6c, 0x74, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x27, 0x2e, 0x69, 0x73,
	0x6f, 0x76, 0x61, 0x6c, 0x65, 0x6e, 0x74, 0x2e, 0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x61, 0x67, 0x67,
	0x72, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x43, 0x68,
	0x61, 0x6e, 0x67, 0x65, 0x52, 0x11, 0x73, 0x74, 0x61, 0x74, 0x65, 0x43, 0x68, 0x61, 0x6e, 0x67,
	0x65, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x2a, 0x6c, 0x0a, 0x0b, 0x53, 0x74, 0x61, 0x74, 0x65,
	0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x0a, 0x0a, 0x06, 0x75, 0x6e, 0x73, 0x70, 0x65, 0x63,
	0x10, 0x00, 0x12, 0x07, 0x0a, 0x03, 0x6e, 0x65, 0x77, 0x10, 0x01, 0x12, 0x0f, 0x0a, 0x0b, 0x65,
	0x73, 0x74, 0x61, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65, 0x64, 0x10, 0x02, 0x12, 0x0f, 0x0a, 0x0b,
	0x66, 0x69, 0x72, 0x73, 0x74, 0x5f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x10, 0x04, 0x12, 0x09, 0x0a,
	0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x10, 0x08, 0x12, 0x0a, 0x0a, 0x06, 0x63, 0x6c, 0x6f, 0x73,
	0x65, 0x64, 0x10, 0x10, 0x12, 0x0f, 0x0a, 0x0b, 0x66, 0x69, 0x72, 0x73, 0x74, 0x5f, 0x72, 0x65,
	0x70, 0x6c, 0x79, 0x10, 0x20, 0x2a, 0x3b, 0x0a, 0x0e, 0x41, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61,
	0x74, 0x6f, 0x72, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x75, 0x6e, 0x6b, 0x6e, 0x6f,
	0x77, 0x6e, 0x10, 0x00, 0x12, 0x0e, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x10, 0x01, 0x12, 0x0c, 0x0a, 0x08, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x10, 0x02, 0x42, 0x55, 0x5a, 0x53, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x63, 0x69, 0x6c, 0x69, 0x75, 0x6d, 0x2f, 0x63, 0x69, 0x6c, 0x69, 0x75, 0x6d, 0x2f, 0x65,
	0x6e, 0x74, 0x65, 0x72, 0x70, 0x72, 0x69, 0x73, 0x65, 0x2f, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e,
	0x73, 0x2f, 0x68, 0x75, 0x62, 0x62, 0x6c, 0x65, 0x2d, 0x66, 0x6c, 0x6f, 0x77, 0x2d, 0x61, 0x67,
	0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x67,
	0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_aggregation_proto_rawDescOnce sync.Once
	file_aggregation_proto_rawDescData = file_aggregation_proto_rawDesc
)

func file_aggregation_proto_rawDescGZIP() []byte {
	file_aggregation_proto_rawDescOnce.Do(func() {
		file_aggregation_proto_rawDescData = protoimpl.X.CompressGZIP(file_aggregation_proto_rawDescData)
	})
	return file_aggregation_proto_rawDescData
}

var file_aggregation_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_aggregation_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_aggregation_proto_goTypes = []interface{}{
	(StateChange)(0),              // 0: isovalent.flow.aggregation.StateChange
	(AggregatorType)(0),           // 1: isovalent.flow.aggregation.AggregatorType
	(*DirectionStatistics)(nil),   // 2: isovalent.flow.aggregation.DirectionStatistics
	(*FlowStatistics)(nil),        // 3: isovalent.flow.aggregation.FlowStatistics
	(*Aggregator)(nil),            // 4: isovalent.flow.aggregation.Aggregator
	(*Aggregation)(nil),           // 5: isovalent.flow.aggregation.Aggregation
	(*timestamppb.Timestamp)(nil), // 6: google.protobuf.Timestamp
	(*durationpb.Duration)(nil),   // 7: google.protobuf.Duration
	(*wrapperspb.BoolValue)(nil),  // 8: google.protobuf.BoolValue
}
var file_aggregation_proto_depIdxs = []int32{
	6, // 0: isovalent.flow.aggregation.DirectionStatistics.first_activity:type_name -> google.protobuf.Timestamp
	6, // 1: isovalent.flow.aggregation.DirectionStatistics.last_activity:type_name -> google.protobuf.Timestamp
	2, // 2: isovalent.flow.aggregation.FlowStatistics.forward:type_name -> isovalent.flow.aggregation.DirectionStatistics
	2, // 3: isovalent.flow.aggregation.FlowStatistics.reply:type_name -> isovalent.flow.aggregation.DirectionStatistics
	1, // 4: isovalent.flow.aggregation.Aggregator.type:type_name -> isovalent.flow.aggregation.AggregatorType
	7, // 5: isovalent.flow.aggregation.Aggregator.ttl:type_name -> google.protobuf.Duration
	8, // 6: isovalent.flow.aggregation.Aggregator.renew_ttl:type_name -> google.protobuf.BoolValue
	4, // 7: isovalent.flow.aggregation.Aggregation.aggregators:type_name -> isovalent.flow.aggregation.Aggregator
	0, // 8: isovalent.flow.aggregation.Aggregation.state_change_filter:type_name -> isovalent.flow.aggregation.StateChange
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_aggregation_proto_init() }
func file_aggregation_proto_init() {
	if File_aggregation_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_aggregation_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DirectionStatistics); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_aggregation_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FlowStatistics); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_aggregation_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Aggregator); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_aggregation_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Aggregation); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_aggregation_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_aggregation_proto_goTypes,
		DependencyIndexes: file_aggregation_proto_depIdxs,
		EnumInfos:         file_aggregation_proto_enumTypes,
		MessageInfos:      file_aggregation_proto_msgTypes,
	}.Build()
	File_aggregation_proto = out.File
	file_aggregation_proto_rawDesc = nil
	file_aggregation_proto_goTypes = nil
	file_aggregation_proto_depIdxs = nil
}