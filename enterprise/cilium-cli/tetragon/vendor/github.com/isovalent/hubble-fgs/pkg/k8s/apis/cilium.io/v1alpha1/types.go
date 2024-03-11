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

package v1alpha1

import (
	"fmt"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumio "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Tracing Policy (TP)

	// TPPluralName is the plural name of Cilium Tracing Policy
	TPPluralName = "tracingpolicies"

	// TPKindDefinition is the kind name of Cilium Tracing Policy
	TPKindDefinition = "TracingPolicy"

	// TPName is the full name of Cilium Egress NAT Policy
	TPName = TPPluralName + "." + ciliumio.GroupName

	// TPNamespacedPluralName is the plural name of Cilium Tracing Policy
	TPNamespacedPluralName = "tracingpoliciesnamespaced"

	// TPNamespacedName
	TPNamespacedName = TPNamespacedPluralName + "." + ciliumio.GroupName

	// TPKindDefinition is the kind name of Cilium Tracing Policy
	TPNamespacedKindDefinition = "TracingPolicyNamespaced"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="tracingpolicynamespaced",path="tracingpoliciesnamespaced",scope="Namespaced",shortName={}
type TracingPolicyNamespaced struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Tracing policy specification.
	Spec TracingPolicySpec `json:"spec"`
}

func (tp *TracingPolicyNamespaced) TpSpec() *TracingPolicySpec {
	return &tp.Spec
}

func (tp *TracingPolicyNamespaced) TpInfo() string {
	return fmt.Sprintf("%s (object:%d/%s) (type:%s/%s)", tp.ObjectMeta.Name, tp.ObjectMeta.Generation, tp.ObjectMeta.UID, tp.TypeMeta.Kind, tp.TypeMeta.APIVersion)
}

func (tp *TracingPolicyNamespaced) TpName() string {
	return tp.ObjectMeta.Name
}

func (tp *TracingPolicyNamespaced) TpNamespace() string {
	return tp.ObjectMeta.Namespace
}

// +genclient
// +genclient:noStatus
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="tracingpolicy",path="tracingpolicies",scope="Cluster",shortName={}
type TracingPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
	// Tracing policy specification.
	Spec TracingPolicySpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TracingPolicyNamespacedList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TracingPolicyNamespaced `json:"items,omitempty"`
}

type TracingPolicySpec struct {
	// +kubebuilder:validation:Optional
	// A list of kprobe specs.
	KProbes []KProbeSpec `json:"kprobes,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of tracepoint specs.
	Tracepoints []TracepointSpec `json:"tracepoints,omitempty"`
	// +kubebuilder:validation:Optional
	// Parser policy specification.
	Parser ParserPolicySpec `json:"parser"`
	// +kubebuilder:validation:Optional
	// File monitoring policy specification.
	FileMonitoring FileSpec `json:"file"`
	// +kubebuilder:validation:Optional
	// File exec monitoring policy specification.
	FileExecMonitoring FileExecSpec `json:"exec"`
	// +kubebuilder:validation:Optional
	// Enable loader events
	Loader bool `json:"loader"`
	// +kubebuilder:validation:Optional
	// A list of uprobe specs.
	UProbes []UProbeSpec `json:"uprobes,omitempty"`

	// +kubebuilder:validation:Optional
	// PodSelector selects pods that this policy applies to
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// A list of list specs.
	Lists []ListSpec `json:"lists,omitempty"`

	// +kubebuilder:validation:Optional
	// A enforcer spec.
	Enforcers []EnforcerSpec `json:"enforcers,omitempty"`

	// +kubebuilder:validation:Optional
	// A list of overloaded options
	Options []OptionSpec `json:"options,omitempty"`
}

func (tp *TracingPolicy) TpSpec() *TracingPolicySpec {
	return &tp.Spec
}

func (tp *TracingPolicy) TpInfo() string {
	return fmt.Sprintf("%s (object:%d/%s) (type:%s/%s)", tp.ObjectMeta.Name, tp.ObjectMeta.Generation, tp.ObjectMeta.UID, tp.TypeMeta.Kind, tp.TypeMeta.APIVersion)
}

func (tp *TracingPolicy) TpName() string {
	return tp.ObjectMeta.Name
}

// OperationSelectorValue represents the value for MatchOperations.
//
// +kubebuilder:validation:Enum=FILE_INVALID;FILE_WRITE;FILE_READ;FILE_DELETE;FILE_CREATE;FILE_RMDIR;FILE_MKDIR;FILE_RENAME;FILE_READDIR;FILE_CHATTR;FILE_EXEC
type OperationSelectorValue = string

type OperationSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// Filter operation.
	Operator string `json:"operator"`
	// Value to compare the argument against.
	Values []OperationSelectorValue `json:"values,omitempty"`
}

type FileActionSelector struct {
	// +kubebuilder:validation:Enum=Post;Block
	// Action to Execute. Post will post an event; Block will also post an event, and additionally block the operation (application will receive an error).
	Action string `json:"action"`
}

// Example: "sha1:f2e2c1b280ae3268c15fd31cd8d2fcec9a984c5f"
type DigestSelectorValue = string

type DigestSelector struct {
	// +kubebuilder:validation:Enum=In;NotIn
	// Filter operation.
	Operator string `json:"operator"`
	// Value to compare the argument against.
	Values []DigestSelectorValue `json:"values,omitempty"`
}

// FileSelector selects file operations.
type FileSelector struct {
	// +kubebuilder:validation:Optional
	// A list of binary exec name filters.
	MatchBinaries []BinarySelector `json:"matchBinaries,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of operation filters.
	MatchOperations []OperationSelector `json:"matchOperations,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of operation filters.
	MatchDigests []DigestSelector `json:"matchDigests,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of namespaces and IDs
	MatchNamespaces []FileNamespaceSelector `json:"matchLinuxNamespaces,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of capabilities and IDs
	MatchCapabilities []FileCapabilitiesSelector `json:"matchLinuxCapabilities,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of actions to execute when this selector matches. For now we only support a single action and users can select either Post or Block. We use an array to potentially support additional actions in the future.
	MatchActions []FileActionSelector `json:"matchActions,omitempty"`
}

// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=128
// +kubebuilder:validation:Pattern=\/.*
// Required and should start with "/". Maximum length is 128 characters.
type PathPrefix = string

type FilePrefixSuffixPattern struct {
	// +kubebuilder:validation:Required
	// The prefix of the path to match.
	Prefix PathPrefix `json:"prefix,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=128
	// The suffix of the file to match. Can be empty. In that case, we only use the prefix. Maximum length is 128 characters.
	Suffix string `json:"suffix,omitempty"`
}

type PathPrefixPattern struct {
	// +kubebuilder:validation:Required
	// The prefix of the path to match. Similar to file_paths.
	Prefix PathPrefix `json:"prefix,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="(self.type == 'FilePrefixSuffix' && has(self.file_prefix_suffix) && !has(self.path_prefix)) || (self.type == 'PathPrefix' && !has(self.file_prefix_suffix) && has(self.path_prefix))",message="Type should match the argument type."
type FilePathPattern struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=FilePrefixSuffix;PathPrefix
	// FilePrefixSuffix can be used to match only files that have a specific prefix and optionally a suffix.
	// PathPrefix has the same semantics as file_paths. This can be used for all files and directories that match a specific prefix.
	Type string `json:"type"`
	// +kubebuilder:validation:Optional
	// Should be defined in the case of type=FilePrefixSuffix.
	FilePrefixSuffix *FilePrefixSuffixPattern `json:"file_prefix_suffix,omitempty"`
	// +kubebuilder:validation:Optional
	// Should be defined in the case of type=PathPrefix.
	PathPrefix *PathPrefixPattern `json:"path_prefix,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="(has(self.file_paths_patterns) && (size(self.file_paths_patterns.filter(c, c.type == 'FilePrefixSuffix')) <= 32)) || (!has(self.file_paths_patterns))",message="We support up to 32 entries with type FilePrefixSuffix under file_paths_patterns."
// +kubebuilder:validation:XValidation:rule="((has(self.file_paths) && (size(self.file_paths) > 0)) || (has(self.file_paths_patterns) && (size(self.file_paths_patterns) > 0))) && (!((has(self.file_paths) && (size(self.file_paths) > 0)) && (has(self.file_paths_patterns) && (size(self.file_paths_patterns) > 0))))",message="You should define exactly one of file_paths or file_paths_patterns."
type FileSpec struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:deprecatedversion:warning="file_paths is deprecated. Use file_paths_patterns instead"
	// What paths to monitor. Only prefixes. Deprecated, please use file_paths_patterns instead.
	Paths []string `json:"file_paths,omitempty"`
	// +kubebuilder:validation:Optional
	// What paths to exclude from monitored paths. Applies both to file_paths and file_paths_patterns.
	PathsExclude []string `json:"file_paths_exclude,omitempty"`
	// +kubebuilder:validation:Optional
	// What paths to monitor using patterns.
	PathsPatterns []FilePathPattern `json:"file_paths_patterns,omitempty"`
	// +kubebuilder:validation:Optional
	// Config flags to enable/disable specific functionality
	Config map[string]string `json:"file_config,omitempty"`
	// +kubebuilder:validation:Optional
	// Selectors to apply before producing trace output. Selectors are ORed.
	Selectors []FileSelector `json:"selectors,omitempty"`
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	// Do monitoring on host files
	MonitorHostFiles bool `json:"monitorHostFiles"`
	// +kubebuilder:validation:Optional
	// This is a label selector which selects Pods. This field follows standard label
	// selector semantics; if present but empty, it selects all pods.
	PodSelector *slimv1.LabelSelector `json:"podSelector,omitempty"`
}

type FileCapabilitiesSelector struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=Effective;Inheritable;Permitted
	// +kubebuilder:default=Effective
	// Type of capabilities
	Type string `json:"type"`
	// +kubebuilder:validation:Enum=In;NotIn
	// Namespace selector operator.
	Operator string `json:"operator"`
	// Capabilities to match.
	Values []string `json:"values"`
}

type FileNamespaceSelector struct {
	// +kubebuilder:validation:Enum=Uts;Ipc;Mnt;Pid;PidForChildren;Net;Time;TimeForChildren;Cgroup;User
	// Namespace selector name.
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:Enum=All;Host;NoHost
	// +kubebuilder:default=All
	// Namespace selector filter type.
	Filter string `json:"filter"`
}

// FileExecSelector selects file operations.
type FileExecSelector struct {
	// +kubebuilder:validation:Optional
	// A list of binary exec name filters.
	MatchBinaries []BinarySelector `json:"matchBinaries,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of operation filters.
	MatchDigests []DigestSelector `json:"matchDigests,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of namespaces and IDs
	MatchNamespaces []FileNamespaceSelector `json:"matchLinuxNamespaces,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of capabilities and IDs
	MatchCapabilities []FileCapabilitiesSelector `json:"matchLinuxCapabilities,omitempty"`
	// +kubebuilder:validation:Optional
	// A list of actions to execute when this selector matches. For now we only support a single action and users can select either Post or Block. We use an array to potentially support additional actions in the future.
	MatchActions []FileActionSelector `json:"matchActions,omitempty"`
}

type FileExecSpec struct {
	// +kubebuilder:default=false
	// Enables process_file_exec events
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Sets the default actions (i.e. what to do if we have selectors and none macthed)
	DefaultActions []FileActionSelector `json:"defaultActions,omitempty"`
	// +kubebuilder:validation:Optional
	// Selectors to apply before producing trace output. Selectors are ORed.
	Selectors []FileExecSelector `json:"selectors,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TracingPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []TracingPolicy `json:"items,omitempty"`
}

type TlsSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts,omitempty"`
}

type TlsSpec struct {
	// TLS enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Enum=socket;tc;cgroup;
	// +kubebuilder:default=tc
	// TLS parser type
	Mode string `json:"mode,omitempty"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []TlsSelector `json:"selectors,omitempty"`
}

type HttpsSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts,omitempty"`
}

type HttpsSpec struct {
	// HTTPS enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []HttpsSelector `json:"selectors,omitempty"`
}

type HttpSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts,omitempty"`
}

type HttpSpec struct {
	// Http enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply TLS parser against. Selectors are ORed.
	Selectors []HttpSelector `json:"selectors,omitempty"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Enable HTTP2 parser
	Http2 bool `json:"http2"`
}

type InterfacePolicySpec struct {
	// Interface enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Interface interval in seconds
	StatsInterval uint32 `json:"statsInterval"`
	// +kubebuilder:validation:Optional
	// Interface packet level BPF
	Packet bool `json:"packet"`
}

type DnsPolicySpec struct {
	// DNS enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// A list of DNS ports
	Ports []uint16 `json:"ports,omitempty"`
	// +kubebuilder:validation:Optional
	// Metrics Configuration
	Metrics *PromMetrics `json:"metrics,omitempty"`
}

type NopSelector struct {
	// +kubebuilder:validation:Optional
	// A list of ports to match. Ports are ORd.
	MatchPorts []uint32 `json:"matchPorts,omitempty"`
}

type NopSpec struct {
	// Nop enable parser
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Selectors to apply Nop parser against. Selectors are ORed.
	Selectors []NopSelector `json:"selectors,omitempty"`
}

type PromMetrics struct {
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Label Filters mask out labels in the metrics
	LabelFilters []string `json:"labelFilters"`
}

type ParserPolicySpec struct {
	// +kubebuilder:validation:Optional
	// A Tls specs.
	Tls TlsSpec `json:"tls"`
	// +kubebuilder:validation:Optional
	// A Tls specs.
	Https HttpsSpec `json:"https"`
	// +kubebuilder:validation:Optional
	// A Http spec.
	Http HttpSpec `json:"http"`
	// +kubebuilder:validation:Optional
	// ICMP policy specification
	Icmp IcmpPolicySpec `json:"icmp"`
	// +kubebuilder:validation:Optional
	// Raw socket policy specification
	Rawsock RawsockPolicySpec `json:"rawsock"`
	// +kubebuilder:validation:Optional
	// UDP policy specification
	Udp UdpPolicySpec `json:"udp"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Interface InterfacePolicySpec `json:"interface"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Dns DnsPolicySpec `json:"dns"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Nop NopSpec `json:"nop"`
	// +kubebuilder:validation:Optional
	// TCP policy specification
	Tcp TcpPolicySpec `json:"tcp"`
	// +kubebuilder:validation:Optional
	// UDP and TCP burst exit checking policy specification
	// +kubebuilder:deprecatedversion:warning="burstExitGen is deprecated. Use networkWatermarksExitGen instead"
	BurstExitGen NetworkWatermarksExitGenPolicySpec `json:"burstExitGen"`
	// +kubebuilder:validation:Optional
	// UDP and TCP watermarks exit checking policy specification
	NetworkWatermarksExitGen NetworkWatermarksExitGenPolicySpec `json:"networkWatermarksExitGen"`
	// +kubebuilder:validation:Optional
	// UDP and TCP heartbeat policy specification
	Heartbeat HeartbeatPolicySpec `json:"heartbeat"`
}

type TcpRttHistogram struct {
	// Enable TCP RTT Histogram
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Configures the expected RTT Max value
	Max uint32 `json:"max"`
	// +kubebuilder:validation:Optional
	// Configures the expected RTT Min value
	Min uint32 `json:"min"`
}

type TcpPolicySpec struct {
	// Enable TCP statistics
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Configures the Stat collection interval in seconds
	StatsInterval uint32 `json:"statsInterval"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	// +kubebuilder:deprecatedversion:warning="burst is deprecated. Use watermarks instead"
	Burst TcpWatermarksPolicySpec `json:"burst"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Watermarks TcpWatermarksPolicySpec `json:"watermarks"`
	// +kubebuilder:validation:Optional
	// Rtt Histogram
	RttHistogram TcpRttHistogram `json:"histogram"`
	// +kubebuilder:validation:Optional
	// TCP latency observability policy specification
	Latency LatencyPolicySpec `json:"latency"`
	// +kubebuilder:validation:Optional
	// Metrics Configuration
	Metrics *PromMetrics `json:"metrics,omitempty"`
	// +kubebuilder:validation:Optional
	// Disable TCP events
	DisableEvents TcpEventDisablePolicySpec `json:"disableEvents"`
}

type TcpWatermarksPolicySpec struct {
	// Enable TCP watermarks observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Optional
	// Configures the watermarks window size in milliseconds
	WindowSize uint32 `json:"windowSize"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	// +kubebuilder:deprecatedversion:warning="triggerPercent is deprecated. Use burstTriggerPercent instead"
	TriggerPercent uint32 `json:"triggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	BurstTriggerPercent uint32 `json:"burstTriggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent under average deemed to be a dip
	DipTriggerPercent uint32 `json:"dipTriggerPercent"`
}

type IcmpPolicySpec struct {
	// Enable ICMP observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// Enable ICMPv6 info message observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	V6Info bool `json:"v6info"`
}

type RawsockPolicySpec struct {
	// Enable raw socket observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// Enable raw socket close events
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	ReportClose bool `json:"reportClose"`
	// +kubebuilder:validation:Optional
	// Metrics Configuration
	Metrics *PromMetrics `json:"metrics,omitempty"`
}

type UdpPolicySpec struct {
	// Enable UDP observability
	Enable bool `json:"enable"`
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	// UDP has two modes one for newer kernels (cgroup) and then an
	// older fallback mode for kprobe use cases. Allow running older
	// kprobe version on newer kernels by setting cgroup knob to false.
	Cgroup bool `json:"cgroup"`
	// +kubebuilder:validation:Optional
	// Configures the Stat collection interval in seconds
	StatsInterval uint32 `json:"statsInterval"`
	// +kubebuilder:validation:Optional
	// Configure socket idle time to delete sockets in seconds
	DeleteIdleSocketInterval uint32 `json:"deleteIdleSocketInterval"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	// kubebuilder:deprecatedversion:warning="burst is deprecated. Use watermarks instead"
	Burst UdpWatermarksPolicySpec `json:"burst"`
	// +kubebuilder:validation:Optional
	// Network policy specification
	Watermarks UdpWatermarksPolicySpec `json:"watermarks"`
	// +kubebuilder:validation:Optional
	// UDP latency observability policy specification
	Latency LatencyPolicySpec `json:"latency"`
	// +kubebuilder:validation:Optional
	// UDP sequence check observability policy specification
	SeqCheck UdpSeqCheckPolicySpec `json:"seqCheck"`
	// +kubebuilder:validation:Optional
	// Metrics Configuration
	Metrics *PromMetrics `json:"metrics,omitempty"`
	// +kubebuilder:validation:Optional
	// Disable UDP events
	DisableEvents UdpEventDisablePolicySpec `json:"disableEvents"`
}

type UdpWatermarksPolicySpec struct {
	// Enable UDP watermarks observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Optional
	// Configures the burst window size in milliseconds
	WindowSize uint32 `json:"windowSize"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	// +kubebuilder:deprecatedversion:warning="triggerPercent is deprecated. Use burstTriggerPercent instead"
	TriggerPercent uint32 `json:"triggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent over average deemed to be a burst
	BurstTriggerPercent uint32 `json:"burstTriggerPercent"`
	// +kubebuilder:default=100
	// +kubebuilder:validation:Optional
	// Configures the percent under average deemed to be a dip
	DipTriggerPercent uint32 `json:"dipTriggerPercent"`
}

type LatencyPolicySpec struct {
	// Enable UDP latency observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Configures the subnets to enable on
	MatchSubnets []string `json:"matchSubnets,omitempty"`
	// +kubebuilder:validation:Optional
	// Configures the ports to enable on
	MatchPorts []uint16 `json:"matchPorts,omitempty"`
	// +kubebuilder:validation:Optional
	// Configures the expected Max Latency value
	Max uint32 `json:"max"`
	// +kubebuilder:validation:Optional
	// Configures the expected Min Latency value
	Min uint32 `json:"min"`
	// +kubebuilder:validation:Optional
	// Configures the clock check interval in seconds
	ClockCheckInterval uint32 `json:"clockCheckInterval"`
	// +kubebuilder:validation:Optional
	// Configures the maximum acceptable clock skew before updating in microseconds
	ClockMaxSkew uint32 `json:"clockMaxSkew"`
	// +kubebuilder:validation:Optional
	// Configures the interfaces to enable on
	Interfaces []string `json:"interfaces,omitempty"`
	// +kubebuilder:validation:Optional
	// Configures the maximum packet size
	MaxPacketSize uint16 `json:"maxPacketSize"`
	// +kubebuilder:validation:Optional
	// Configures the interfaces check interval in seconds
	InterfacesCheckInterval uint32 `json:"interfacesCheckInterval"`
}

type UdpSeqCheckPolicySpec struct {
	// Enable UDP sequence check observability
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:validation:Optional
	// Configures the UDP sequence checker application
	AppId uint64 `json:"appId"`
	// +kubebuilder:validation:Optional
	// Configures the ports to enable on
	Ports []uint16 `json:"ports,omitempty"`
}

type NetworkWatermarksExitGenPolicySpec struct {
	// Enable watermarks checks for end events from userland
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Optional
	// Configures the checking interval in milliseconds
	Interval uint32 `json:"interval"`
}

type HeartbeatPolicySpec struct {
	// Enable heartbeat
	// +kubebuilder:default=true
	// +kubebuilder:validation:Optional
	Enable bool `json:"enable"`
	// +kubebuilder:default=60
	// +kubebuilder:validation:Optional
	// Configures the heartbeat interval in seconds
	Interval uint32 `json:"interval"`
	// +kubebuilder:default=6399
	// +kubebuilder:validation:Optional
	// Configures the UDP port
	UdpPort uint32 `json:"udpPort"`
	// +kubebuilder:default=6399
	// +kubebuilder:validation:Optional
	// Configures the TCP port
	TcpPort uint32 `json:"tcpPort"`
}

type TcpEventDisablePolicySpec struct {
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable connect events
	DisableConnect bool `json:"disableConnect"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable close events
	DisableClose bool `json:"disableClose"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable accept events
	DisableAccept bool `json:"disableAccept"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable listen events
	DisableListen bool `json:"disableListen"`
}

type UdpEventDisablePolicySpec struct {
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable connect events
	DisableConnect bool `json:"disableConnect"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable listen events
	DisableListen bool `json:"disableListen"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable close events
	DisableClose bool `json:"disableClose"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:Optional
	// Disable stats events, write to metrics directly
	DisableStats bool `json:"disableStats"`
}
