package hostnetworking

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/vishvananda/netlink"
)

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
	// Yields: DetermineTunnelMode, MoveLocalPolicyRule
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
	// SetupPolicyRoutingRules will create two policy routing rules
	// which direct marked packets to their appropriate routing
	// tables.
	SetupPolicyRoutingRules
	// SetupPolicyRoutingTables will create the necessary routing
	// table entries to support Cilium's transparent proxying.
	SetupPolicyRoutingTables
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

// Config are external parameters which
// drive the Manager's host networking business logic.
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
	return ConfigureIPv6, nil
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
			return nil
		}
		var localRule *netlink.Rule
		for _, rule := range rules {
			if rule.Table == localRTTable {
				localRule = &rule
			}
		}
		// here we will search for routing policy
		// rule for the local lookup table and move
		// it to prio 100 if need be.
		switch {
		case localRule == nil:
			// no routing policy for local table
			// do nothing?
		case localRule.Priority == 100:
			// routing policy for local table
			// already set to 100, do nothing.
		case localRule.Priority == 0:
			// create prio 100 rule first and then
			// delete old one, order matters here to
			// not black hole traffic.
			clone := *localRule
			clone.Priority = 100
			err := netlink.RuleAdd(&clone)
			if err != nil {
				return err
			}
			if err := netlink.RuleDel(localRule); err != nil {
				// failed to delete prio 0 rule, delete
				// the cloned rule we successfully inserted.
				err := netlink.RuleDel(localRule)
				// about to to return the above error anyway,
				// lets just communicate whether cleanup was
				// successful or not.
				return fmt.Errorf("%v : Cleanup Error: %v", err, err)
			}
		}
		return nil
	}

	if !m.IPv4Addr.IsUnspecified() {
		err := move(netlink.FAMILY_V4)
		if err != nil {
			return -1, fmt.Errorf("failed to move policy rule for IPv4 local routing table: %w", err)
		}
	}

	if !m.IPv6Addr.IsUnspecified() {
		err := move(netlink.FAMILY_V6)
		if err != nil {
			return -1, fmt.Errorf("failed to move policy rule for IPv6 local routing table: %w", err)
		}
	}

	return SetupPolicyRoutingRules, nil
}

func (m *Manager) SetupPolicyRoutingRules(context.Context) (State, error) {
	const (
		ProxyRTTable   = 2005
		ToProxyRTTable = 2004
	)
	// TODO(ldelossa) this is only checked during setup of policy
	// routing, and not on the move of the routing rule for the local
	// routing table. is this correct?
	if m.conf.Mode == "ipvlan" {
		return 0, nil
	}

	setup := func(family int) error {
		// determine existence of the two rules we
		// are concerned with.
		rules, err := netlink.RuleList(family)
		if err != nil {
			return fmt.Errorf("failed to list rules for ip family %v: %w", family, err)
		}
		var toProxyRule *netlink.Rule
		var fromIngressRule *netlink.Rule
		for _, rule := range rules {
			switch rule.Table {
			case ProxyRTTable:
				fromIngressRule = &rule
			case ToProxyRTTable:
				toProxyRule = &rule
			}
		}

		// unconditionally add toProxyRule if it does not exist
		if toProxyRule == nil {
			err := netlink.RuleAdd(&netlink.Rule{
				Priority: 10,
				Table:    ProxyRTTable,
			})
			if err != nil {
				return fmt.Errorf("failed to add to_proxy routing table rule for family %v: %w", family, err)
			}
		}

		// add or remove fromIngressRule based on EnableEndpointRoutes
		// rule.
		//
		// The two missing truth table entries result in no-ops and are omitted.
		switch {
		case fromIngressRule == nil && m.conf.EnableEndpointRoutes == false:
			// create rule
			err := netlink.RuleAdd(&netlink.Rule{
				Priority: 10,
				Table:    ProxyRTTable,
			})
			if err != nil {
				return fmt.Errorf("failed to add from_ingress routing table rule for family %v: %w", family, err)
			}
		case fromIngressRule != nil && m.conf.EnableEndpointRoutes == true:
			// delete rule
			netlink.RuleDel(fromIngressRule)
			if err != nil {
				return fmt.Errorf("failed to delete from_ingress routing table rule for family %v: %w", family, err)
			}
		}
		return nil
	}

	if !m.IPv4Addr.IsUnspecified() {
		err := setup(netlink.FAMILY_V4)
		if err != nil {
			return -1, fmt.Errorf("failed to create policy routing rules for IPv4", err)
		}
	}

	if !m.IPv6Addr.IsUnspecified() {
		err := setup(netlink.FAMILY_V6)
		if err != nil {
			return -1, fmt.Errorf("failed to create policy routing rules for IPv6", err)
		}
	}

	return SetupPolicyRoutingTables, nil
}

func (m *Manager) SetupPolicyRoutingTables(ctx context.Context) (State, error) {
	const (
		ProxyRTTable   = 2005
		ToProxyRTTable = 2004
	)

	setup := func(ctx context.Context, family int) error {
		routes, err := netlink.RouteList(nil, family)
		if err != nil {
			return err
		}

		// we'll use these variables to hold various addresses
		// we need based on the provided family.
		var ip net.IP
		var mask net.IPMask
		var zeroIP net.IP
		switch family {
		case netlink.FAMILY_V4:
			ip = m.IPv4Addr
			mask = net.CIDRMask(32, 32)
			zeroIP = net.IPv4zero
		case netlink.FAMILY_V6:
			ip = m.IPv6Addr
			mask = net.CIDRMask(128, 128)
			zeroIP = net.IPv6zero
		}

		var localHostRoute *netlink.Route
		var defaultRoute *netlink.Route
		for _, route := range routes {
			switch {
			case route.Table == ProxyRTTable && route.Dst.IP.Equal(ip):
				localHostRoute = &route
			case route.Table == ProxyRTTable && route.Dst.IP.Equal(net.IPv4zero):
				defaultRoute = &route
			}
		}

		var loop netlink.Link
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, link := range links {
			if link.Attrs().Flags&net.FlagLoopback > 0 {
				loop = link
			}
		}
		if loop == nil {
			return fmt.Errorf("no loopback device detected")
		}

		// we unconditionally setup a route to 0.0.0.0/0 for local delivery
		// route family is determined by ip length.
		err = netlink.RouteReplace(&netlink.Route{
			Table: ToProxyRTTable,
			Dst: &net.IPNet{
				IP:   zeroIP,
				Mask: mask,
			},
			Type:      2, // RTN_LOCAL
			LinkIndex: loop.Attrs().Index,
		})
		if err != nil {
			return err
		}

		// if endpoint routes is enabled and either of the
		// ProxyRTTable routes exist, delete them, we won't
		// use the ProxyRTTable rules.
		//
		// this block early returns.
		if m.conf.EnableEndpointRoutes {
			if localHostRoute != nil {
				err := netlink.RouteDel(localHostRoute)
				if err != nil {
					return err
				}
			}
			if defaultRoute != nil {
				err := netlink.RouteDel(defaultRoute)
				if err != nil {
					return err
				}
				return nil
			}
			return nil
		}

		if localHostRoute == nil {
			err := netlink.RouteAdd(&netlink.Route{
				Table: ProxyRTTable,
				Dst: &net.IPNet{
					IP:   ip,
					Mask: mask,
				},
				LinkIndex: m.conf.HostDev1.Attrs().Index,
			})
			if err != nil {
				return err
			}
			if defaultRoute == nil {
				err := netlink.RouteAdd(&netlink.Route{
					Table: ProxyRTTable,
					Dst: &net.IPNet{
						IP:   zeroIP,
						Mask: net.CIDRMask(0, 0),
					},
					Via: &netlink.Via{
						AddrFamily: family,
						Addr:       ip,
					},
				})
				if err != nil {
					return err
				}
			}
		}
		return nil
	}

	if !m.IPv4Addr.IsUnspecified() {
		err := setup(ctx, netlink.FAMILY_V4)
		if err != nil {
			return -1, fmt.Errorf("failed to create policy routing rules for IPv4", err)
		}
	}

	if !m.IPv6Addr.IsUnspecified() {
		err := setup(ctx, netlink.FAMILY_V6)
		if err != nil {
			return -1, fmt.Errorf("failed to create policy routing rules for IPv6", err)
		}
	}
}
