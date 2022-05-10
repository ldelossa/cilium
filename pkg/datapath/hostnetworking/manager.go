package hostnetworking

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// State enumerates the possible states
// our Manager can transition through.
type State int

const (
	// ConfigureIPv4 will configure and report
	// the IPv4 address managed by Cilium.
	//
	// This state is driven from DaemonConfg.EnableIPv4
	//
	// Yields: ConfigureIPv6
	ConfigureIPv4 State = iota
	// ConfigureIPv6 will configure and report
	// the IPv6 address managed by Cilium.
	//
	// This state is driven from DaemonConfg.EnableIPv6
	//
	// Yields: DeterminePolicyRouting
	ConfigureIPv6
	// DeterminePolicyRouting is a decision which branches
	// the state diagram if Cilium's policy routing features
	// are requested.
	//
	// PolicyRouting is used for transparent proxying to
	// and from userspace proxy such as Envoy or the Cilium
	// agent itself.
	//
	// If PolicyRouting is determined to be not configured
	// this state must cleanup any previous PolicyRouting
	// artifacts.
	//
	// Yields:
	DeterminePolicyRouting
	// MoveLocalPolicyRule is the first step in policy
	// routing configuration.
	//
	// The local policy rule (prio 0) will be moved out of the way for
	// both IPv6 (if enabled) and IPv4 (if enabled) allowing
	// Cilium's policy rules to take preference.
	//
	// Yields: SetupPolicyRoutingRules
	MoveLocalPolicyRule
	// SetupPolicyRoutingRules creates the necessary policy
	// routing rules and populates the necessary routing
	// tables to support Cilium's policy routing configuration.
	SetupPolicyRoutingRules
	// DetermineMode will evaluate the requested Mode,
	// requested TunnelMode, and whether NodePort configuration
	// is requested.
	//
	// Once the provided configuration is evaluated to a desired
	// linux interface configuration, any irrelevant network interfaces
	// or bpf programs are removed.
	//
	// Specific states are then yielded to create the correct network interfaces
	// for the desired configuration.
	//
	// Mode       |    Yields
	// ______________________
	// ipip            ConfigureIPIPMode
	// direct          ConfigureNativeDevices
	// ipvaln          ConfigureNativeDevices
	// direct          ConfigureNativeDevices
	// tunnel          ConfigureTunnelMode
	//
	// As a special case, if config.NodePort is true
	// this state will yield ConfigureNativeDevices
	DetermineNetworking
	// ConnfigureIPIPMode will configure the requested
	// IPIP interface.
	ConfigureIPIPMode
	// ConfigureNativeDevices is entered when:
	// config.Mode == "direct" || config.Mode == "ipvaln || config.NodePort == true
	//
	// This state checks the existence of config.NativeDevs, and if they exist
	// writes them to config.RunDir/device.state
	ConfigureNativeDevices
	// ConfigureTunnelMode evalutes the TunnelMode configuration and
	// creates the necessary linux networking interfaces to support
	// the requested tunneling mode.
	ConfigureTunnelMode
	// ConfigureHostLoadBalancing will configure the linux host
	// for Cilium load balancing if requested.
	//
	// If Cilium load balancing is not enabled any necessary
	// cleanup will be performed.
	ConfigureHostLoadBalancing
)

// Config is a struct of external parameters which
// drive the Manager's business logic.
//
// The DaemonConfig is embedded to provide the same general
// configuration flags the Agent possesses.
type Config struct {
	// embedded DaemonConfig since a lot of parameters
	// we need exist here.
	*option.DaemonConfig

	// additional configuration necessary for
	// linux host networking setup but not in DaemonConfig.
	Mode       string
	CgroupRoot string
	BPFFSRoot  string
	MTU        string
	BPFCPU     string
	ArgNrCPUs  string

	// cilium_host
	HostDev1 netlink.Link
	// cilium_net
	HostDev2 netlink.Link
}

// Manager coordinates and oversees
// the necessary Linux host networking
// details for the Cilium agent runtime.
//
// Manager is also responsible for generating
// .h files necessary for Cilium's bpf layer.
//
// Manager assumes base devices are already configured
// and passed to it.
type Manager struct {
	state State
	conf  *Config

	// stateful fields populated during run of the
	// manager

	// the configured IPv4 address, nil if DaemonConfig
	// EnableIPv4 is false.
	IPv4Addr net.IP
	// the configured IPv6 address, nil if DaemonConfig
	// EnableIPv6 is false.
	IPv6Addr net.IP
}

// Run places the Manager into action, configuring
// the host networking.
//
// This method will traverse the State graph until a un-recoverable
// error occurs or the host networking is configured correctly.
func (m *Manager) Run(ctx context.Context) error {
	s := map[State]func(*Manager, context.Context) (State, error){
		ConfigureIPv4: (*Manager).ConfigureIPv4, // method expression
	}

	var err error

	m.state, err = s[m.state](m, ctx)
	if err != nil {
		return err
	} else {
		// recurse
		m.Run(ctx)
	}
	return nil
}

func (m *Manager) ConfigureIPv4(ctx context.Context) (State, error) {
	switch m.conf.EnableIPv4 {
	case true:
		addrs, err := netlink.AddrList(m.conf.HostDev1, netlink.FAMILY_V4)
		if err != nil {
			return -1, fmt.Errorf("Failed to obtain IPv4 addresses on HostDev1: %w", err)
		}

		// gen IPv4 addr
		m.IPv4Addr = node.GetInternalIPv4Router()
		if m.IPv4Addr.IsUnspecified() {
			return -1, fmt.Errorf("IPv4 mode enabled could could obtain IPv4 address")
		}

		// if already set, early return.
		for _, addr := range addrs {
			if addr.IP.Equal(m.IPv4Addr) {
				return ConfigureIPv6, nil
			}
		}

		// lets set it.
		err = netlink.AddrAdd(m.conf.HostDev1, &netlink.Addr{
			IPNet: &net.IPNet{IP: m.IPv4Addr, Mask: net.CIDRMask(32, 32)},
		})
		if err != nil {
			return -1, fmt.Errorf("Failed to set IPv4 address on HostDev1: %w", err)
		}
	case false:
		// log that IPv4 was set to disabled.
	}
	return ConfigureIPv6, nil
}

func (m *Manager) ConfigureIPv6(ctx context.Context) (State, error) {
	switch m.conf.EnableIPv6 {
	case true:
		addrs, err := netlink.AddrList(m.conf.HostDev1, netlink.FAMILY_V6)
		if err != nil {
			return -1, fmt.Errorf("Failed to obtain IPv6 addresses on HostDev1: %w", err)
		}

		// gen IPv4 addr
		m.IPv6Addr = node.GetIPv6()
		if m.IPv6Addr.IsUnspecified() {
			return -1, fmt.Errorf("IPv4 mode enabled could could obtain IPv4 address")
		}

		// if already set, early return.
		for _, addr := range addrs {
			if addr.IP.Equal(m.IPv6Addr) {
				return ConfigureIPv6, nil
			}
		}

		// lets set it.
		err = netlink.AddrAdd(m.conf.HostDev1, &netlink.Addr{
			IPNet: &net.IPNet{IP: m.IPv6Addr, Mask: net.CIDRMask(128, 128)},
		})
		if err != nil {
			return -1, fmt.Errorf("Failed to set IPv4 address on HostDev1: %w", err)
		}
	case false:
		// log that IPv4 was set to disabled.
	}
	return DeterminePolicyRouting, nil
}

func (m *Manager) DeterminePolicyRouting(ctx context.Context) (State, error) {
	// TODO: pretty sure we should handle lines 162-163
	// and 200-201 from init.sh here - if IPv6 or IPv4
	// is not enabled the policy rules are simply deleted
	// in the setup_proxy_rules() function. I think we
	// this is an attempt to "cleanup" but we can do that
	// here much cleaner.
	if m.conf.InstallIptRules {
		return MoveLocalPolicyRule, nil
	}
	return DetermineNetworking, nil
}

func (m *Manager) MoveLocalPolicyRule(ctx context.Context) (State, error) {
	const (
		localRTTable = 255 // default seen via /etc/iproute2/rt_tables
		// the kernel does not specify a priority for the default
		// priority 0 rule.
		// thus the netlink library assigns this rule the default value
		// of "-1".
		Prio = -1
	)
	move := func(family int) error {
		rules, err := netlink.RuleList(family)
		if err != nil {
			return err
		}

		// we are going to use this as an indicator that
		// the family is not supported - for example ipv6
		// stack is disabled and there is nothing to do.
		if len(rules) == 0 {
			return fmt.Errorf("family is disabled")
		}

		rulesByPrio := map[int]*netlink.Rule{}
		for i := range rules {
			rulesByPrio[rules[i].Priority] = &rules[i]
			// oddly enough, the netlink library
			// does not return rules with the
			// family defined.
			// even despite filtering for the family
			// in the above RuleList call.
			rules[i].Family = family
		}

		// if the 0 priority rule does not exist
		// we have nothing to move out of the way.
		if _, ok := rulesByPrio[Prio]; !ok {
			return nil
		}

		if rulesByPrio[Prio].Table != localRTTable {
			return fmt.Errorf("rule with priority zero points to unexpected routing table: %v", rulesByPrio[Prio].Table)
		}

		clone := *rulesByPrio[Prio]
		clone.Priority = 100

		if err := netlink.RuleAdd(&clone); err != nil {
			return fmt.Errorf("failed to add rule: %v", err)
		}

		if err := netlink.RuleDel(rulesByPrio[Prio]); err != nil {
			// reverse what we just did.
			errStr := fmt.Sprintf("failed to remove prio 0 rule: %s", err.Error())
			if err := netlink.RuleDel(&clone); err != nil {
				errStr = fmt.Sprintf("%s failed to cleanup prio 100 rule: %s", errStr, err.Error())
			}
			return fmt.Errorf(errStr)
		}

		return nil
	}

	if m.conf.EnableIPv4 {
		err := move(netlink.FAMILY_V4)
		if err != nil {
			return -1, fmt.Errorf("failed to move policy rule for IPv4 local routing table: %w", err)
		}
	}

	if m.conf.EnableIPv6 {
		err := move(netlink.FAMILY_V6)
		if err != nil {
			return -1, fmt.Errorf("failed to move policy rule for IPv6 local routing table: %w", err)
		}
	}

	return SetupPolicyRoutingRules, nil
}

func (m *Manager) SetupPolicyRoutingRules(context.Context) (State, error) {
	const (
		ProxyRTTable      = 2005
		ToProxyRTTable    = 2004
		ToProxyRulePrio   = 9
		FromProxyRulePrio = 10
	)
	// TODO(ldelossa) this is only checked during setup of policy
	// routing, and not on the move of the routing rule for the local
	// routing table. is this correct?
	if m.conf.Mode == "ipvlan" {
		return 0, nil
	}

	setup := func(family int) error {
		rules, err := netlink.RuleList(family)
		if err != nil {
			return err
		}

		// we are going to use this as an indicator that
		// the family is not supported - for example ipv6
		// stack is disabled and there is nothing to do.
		//
		// this is an error since IPv6 is enabled but
		// is seemingly disabled on the host.
		if len(rules) == 0 {
			return fmt.Errorf("family is disabled")
		}

		rulesByPrio := map[int]*netlink.Rule{}
		for i := range rules {
			rulesByPrio[rules[i].Priority] = &rules[i]
			// oddly enough, the netlink library
			// does not return rules with the
			// family defined.
			// even despite filtering for the family
			// in the above RuleList call.
			rules[i].Family = family
		}

		// handle to-proxy rules and routes.
		var (
			toProxyDefaultRoute   net.IPNet
			toProxyRTDefaultRoute netlink.Route
		)
		switch family {
		case netlink.FAMILY_V4:
			toProxyDefaultRoute = net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, 32),
			}
			// TODO: This is not correct, we need to make
			// a type: unix.RTN_LOCAL route here but the
			// netlink library is not allowing this.
			// before this code is used fixed this.
			toProxyRTDefaultRoute = netlink.Route{
				Type:      unix.RTN_UNICAST,
				Dst:       &toProxyDefaultRoute,
				LinkIndex: 1, // loopback
				Table:     ProxyRTTable,
			}
		case netlink.FAMILY_V6:
			toProxyDefaultRoute = net.IPNet{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, 128),
			}
			toProxyRTDefaultRoute = netlink.Route{
				Type:      unix.RTN_UNICAST,
				Dst:       &toProxyDefaultRoute,
				LinkIndex: 1, // loopback
				Table:     ToProxyRTTable,
			}
		}

		if _, ok := rulesByPrio[ToProxyRulePrio]; !ok {
			rule := netlink.NewRule()
			rule.Priority = ToProxyRulePrio
			rule.Table = ProxyRTTable
			rule.Family = family
			if err := netlink.RuleAdd(rule); err != nil {
				return fmt.Errorf("failed to create to-proxy rule: %w", err)
			}
			if err := netlink.RouteReplace(&toProxyRTDefaultRoute); err != nil {
				return fmt.Errorf("failed to create to-proxy route: %w", err)
			}
		}

		// handle from-proxy rules and routes.
		//
		// if EnableEndpointRoutes is true, from-proxy
		// rules and routes should not exist.
		var (
			hostRouteNet        net.IPNet
			defaultRouteNet     net.IPNet
			proxyRTHostRoute    netlink.Route
			proxyRTDefaultRoute netlink.Route
		)
		switch family {
		case netlink.FAMILY_V4:
			hostRouteNet = net.IPNet{
				IP:   m.IPv4Addr,
				Mask: net.CIDRMask(32, 32),
			}
			defaultRouteNet = net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, 32),
			}
			proxyRTHostRoute = netlink.Route{
				Table:     ProxyRTTable,
				Dst:       &hostRouteNet,
				LinkIndex: m.conf.HostDev1.Attrs().Index,
			}
			proxyRTDefaultRoute = netlink.Route{
				Table:     ProxyRTTable,
				Dst:       &defaultRouteNet,
				LinkIndex: m.conf.HostDev1.Attrs().Index,
			}
		case netlink.FAMILY_V6:
			hostRouteNet = net.IPNet{
				IP:   m.IPv6Addr,
				Mask: net.CIDRMask(128, 128),
			}
			defaultRouteNet = net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, 128),
			}
			proxyRTHostRoute = netlink.Route{
				Table:     ProxyRTTable,
				Dst:       &hostRouteNet,
				LinkIndex: m.conf.HostDev1.Attrs().Index,
			}
			proxyRTDefaultRoute = netlink.Route{
				Table:     ProxyRTTable,
				Dst:       &defaultRouteNet,
				LinkIndex: m.conf.HostDev1.Attrs().Index,
			}
		}

		fromProxyIngressRule, ok := rulesByPrio[FromProxyRulePrio]
		switch {
		case !ok && !m.conf.EnableEndpointRoutes:
			// FromProxyRule does not exist, and
			// EnableEndpointRoutes is false, create
			// the rule and update routing table.
			rule := netlink.NewRule()
			rule.Priority = FromProxyRulePrio
			rule.Family = family
			rule.Table = ProxyRTTable
			// TODO: need fwmark here
			if err := netlink.RuleAdd(rule); err != nil {
				return fmt.Errorf("failed to add from-proxy rule: %w", err)
			}

			// add the routes into ProxyRTTable
			// ip route replace table $PROXY_RT_TABLE $IP4_HOST/32 dev $HOST_DEV1
			if err := netlink.RouteReplace(&proxyRTHostRoute); err != nil {
				return fmt.Errorf("failed to create from-proxy host route: %w", err)
			}
			// ip route replace table $PROXY_RT_TABLE default via $IP4_HOST
			if err := netlink.RouteReplace(&proxyRTDefaultRoute); err != nil {
				return fmt.Errorf("failed to create from-proxy default route: %w", err)
			}
		case ok && m.conf.EnableEndpointRoutes:
			// fromProxyIngressRule exists and EnableEndPointsRoute is true,
			// delete this rule
			if err := netlink.RuleDel(fromProxyIngressRule); err != nil {
				return fmt.Errorf("failed to delete from-proxy rule: %w", err)
			}

			// ip route delete table $PROXY_RT_TABLE $IP4_HOST/32 dev $HOST_DEV1 2>/dev/null || true
			if err := netlink.RouteDel(&proxyRTHostRoute); err != nil {
				return fmt.Errorf("failed to delete from-proxy host route: %w", err)
			}
			// ip route delete table $PROXY_RT_TABLE default via $IP4_HOST 2>/dev/null || true
			if err := netlink.RouteDel(&proxyRTDefaultRoute); err != nil {
				return fmt.Errorf("failed to delete from-proxy default route: %w", err)
			}
		case !ok && m.conf.EnableEndpointRoutes:
			// rule does not exist, EnableEdnpointRoutes is true,
			// no-op, nothing to delete.
		case ok && !m.conf.EnableEndpointRoutes:
			// rule exists, EnableEndpointRoutes is false,
			// no-op, rule is already inplace.
		}
		return nil
	}

	if m.conf.EnableIPv4 {
		err := setup(netlink.FAMILY_V4)
		if err != nil {
			return -1, fmt.Errorf("failed to create policy routing rules for IPv4: %v", err)
		}
	}

	if m.conf.EnableIPv6 {
		err := setup(netlink.FAMILY_V6)
		if err != nil {
			return -1, fmt.Errorf("failed to create policy routing rules for IPv6: %v", err)
		}
	}

	return DetermineNetworking, nil
}
