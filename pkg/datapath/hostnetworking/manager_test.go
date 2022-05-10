package hostnetworking

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	netNSProc = "/proc/%d/ns/net"
)

// Harness provides a test harness for testing the Manager.
//
// This harness will switch our running process into it's own
// net namespace along with creating the necessary interfaces
// the manager expects.
type Harness struct {
	pid      int
	nsID     string
	HostDev1 netlink.Link
	HostDev2 netlink.Link
}

func NewHarness(t *testing.T) *Harness {
	h := &Harness{}
	h.pid = os.Getpid()
	h.nsID = h.getNSID(t)
	t.Logf("harness created for pid %d with initial network namespace %s", h.pid, h.nsID)
	return h
}

// Setup will instruct the test Harness
// to enter a new network namespace and create
// the appropriate dummy devices used for testing.
//
// This is the same as calling Harness.Unshare
// and Harness.CreateDevs in succession.
func (h *Harness) Setup(t *testing.T) {
	h.Unshare(t)
	h.CreateDevs(t)
}

func (h *Harness) getNSID(t *testing.T) string {
	dir := fmt.Sprintf(netNSProc, h.pid)
	netNSID, err := os.Readlink(dir)
	if err != nil {
		t.Fatalf("failed to read net ns link: %v", err)
	}
	netNSIDBytes := []byte(netNSID)
	// cut out the numeric id portion of net:[12345679] from netNSID
	return string(netNSID[bytes.IndexRune(netNSIDBytes, '[')+1 : len(netNSIDBytes)-1])
}

// Unshare will move our current process to
// a new network namespace or fatal the test
// if this fails.
func (h *Harness) Unshare(t *testing.T) {
	if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		t.Fatalf("failed to unshare net ns: %v", err)
	}
	newNSID := h.getNSID(t)
	if newNSID == h.nsID {
		t.Fatalf("net ns id did not change after unshare. id remained: %v", h.nsID)
	}
	h.nsID = newNSID
	t.Logf("harness moved pid %d to network namepace %s", h.pid, h.nsID)
}

// CreateDevs creates the necessary interfaces within
// the current netNS the manager expects.
//
// on error the provided test will fatal.
func (h *Harness) CreateDevs(t *testing.T) {
	peerMAC, _ := net.ParseMAC("00:12:34:56:78:02")

	dev1 := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:        "cilium_host",
			MTU:         1500,
			TxQLen:      100,
			NumTxQueues: 4,
			NumRxQueues: 8,
		},
		PeerName:         "cilium_net",
		PeerHardwareAddr: peerMAC,
	}
	if err := netlink.LinkAdd(dev1); err != nil {
		t.Fatalf("failed to create cilium_host and cilium_net veth pair: %v", err)
	}

	dev2, err := netlink.LinkByName("cilium_net")
	if err != nil {
		t.Fatalf("failed to lookup veth pair cilium_net: %v", err)
	}
	h.HostDev1 = dev1
	h.HostDev2 = dev2
	if err := netlink.LinkSetUp(h.HostDev1); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(h.HostDev2); err != nil {
		t.Fatal(err)
	}
	// we'll have to make sure lo is up in the appropriate namespace
	// since our tests utilize this.
	lo, _ := netlink.LinkByName("lo")
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
}

// TestHarness ensures our harness correctly
// sets our testing environment.
func TestHarness(t *testing.T) {
	h := NewHarness(t)
	h.Setup(t)

	_, err := netlink.LinkByName("cilium_host")
	if err != nil {
		t.Fatalf("failed to get cilium_host link: %v", err)
	}
	_, err = netlink.LinkByName("cilium_net")
	if err != nil {
		t.Fatalf("failed to get cilium_net link: %v", err)
	}
}

// TestConfigureIPv4 confirms the ConfigureIPv4 state
// correctly configures the "cilium_host" device.
func TestConfigureIPv4(t *testing.T) {
	h := NewHarness(t)
	h.Setup(t)

	// enable IPv4 in daemon config
	dConf := option.DaemonConfig{
		EnableIPv4: true,
	}

	// set the internal router's (agent) IPv4 address
	ip := net.ParseIP("192.168.0.10")
	node.SetInternalIPv4Router(ip)

	m := Manager{
		conf: &Config{
			DaemonConfig: &dConf,
			HostDev1:     h.HostDev1,
		},
	}

	state, err := m.ConfigureIPv4(context.Background())
	if err != nil {
		t.Fatalf("failed to configure cilium_host ipv4 address: %v", err)
	}
	if state != ConfigureIPv6 {
		t.Fatalf("unexpected state: got %d want %d", state, ConfigureIPv6)
	}

	// check our link state
	link, err := netlink.LinkByName(m.conf.HostDev1.Attrs().Name)
	if err != nil {
		t.Fatalf("failed to retrieve cilium_host link by name: %v", err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) == 0 {
		t.Fatalf("no address assigned to cilium_host")
	}
	if !addrs[0].IP.Equal(ip) {
		t.Fatalf("incorrect ip assigned to cilium_host. got %v, want %v", addrs[0].IP, ip)
	}
}

func TestConfigureIPv6(t *testing.T) {
	h := NewHarness(t)
	h.Setup(t)

	// enable IPv4 in daemon config
	dConf := option.DaemonConfig{
		EnableIPv6: true,
	}

	// set the internal router's (agent) IPv4 address
	ip := net.ParseIP("2001:db8::68")
	node.SetIPv6(ip)

	m := Manager{
		conf: &Config{
			DaemonConfig: &dConf,
			HostDev1:     h.HostDev1,
		},
	}

	state, err := m.ConfigureIPv6(context.Background())
	if err != nil {
		t.Fatalf("failed to configure cilium_host ipv4 address: %v", err)
	}
	if state != DeterminePolicyRouting {
		t.Fatalf("unexpected state: got %d want %d", state, DeterminePolicyRouting)
	}

	// check our link state
	link, err := netlink.LinkByName(m.conf.HostDev1.Attrs().Name)
	if err != nil {
		t.Fatalf("failed to retrieve cilium_host link by name: %v", err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) == 0 {
		t.Fatalf("no address assigned to cilium_host")
	}
	if !addrs[0].IP.Equal(ip) {
		t.Fatalf("incorrect ip assigned to cilium_host. got %v, want %v", addrs[0].IP, ip)
	}

}

// TestDeterminePolicyRouting confirms the DeterminePolicyRouting
// state correctly identifies if policy routing should be configured.
func TestDeterminePolicyRouting(t *testing.T) {
	dConf := option.DaemonConfig{
		InstallIptRules: true,
	}
	m := Manager{
		conf: &Config{
			DaemonConfig: &dConf,
		},
	}
	state, err := m.DeterminePolicyRouting(context.Background())
	if err != nil {
		t.Fatalf("failed to determine policy routing: %v", err)
	}
	if state != MoveLocalPolicyRule {
		t.Fatalf("got: %v, want: %v", state, MoveLocalPolicyRule)
	}

	m.conf.InstallIptRules = false
	state, err = m.DeterminePolicyRouting(context.Background())
	if err != nil {
		t.Fatalf("failed to determine policy routing: %v", err)
	}
	if state != DetermineNetworking {
		t.Fatalf("got: %v, want: %v", state, MoveLocalPolicyRule)
	}
}

// TODO: Delete this, currently a scratch space for debugging
// netlink.
func TestNetLink(t *testing.T) {
	h := NewHarness(t)
	h.Setup(t)

	lo, _ := netlink.LinkByName("lo")
	// bring the interface up
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}

	// add a gateway route
	defaultRouteNet := net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.CIDRMask(0, 32),
	}

	route := netlink.Route{
		Type:      unix.RTN_UNICAST,
		Dst:       &defaultRouteNet,
		LinkIndex: 1,
		Table:     2005,
	}
	if err := netlink.RouteAdd(&route); err != nil {
		t.Log(err)
	}
	time.Sleep(999 * time.Second)
}

func TestMoveLocalPolicyRule(t *testing.T) {
	h := NewHarness(t)
	h.Setup(t)

	dConf := option.DaemonConfig{
		EnableIPv4: true,
		EnableIPv6: true,
	}

	m := Manager{
		conf: &Config{
			DaemonConfig: &dConf,
		},
	}
	state, err := m.MoveLocalPolicyRule(context.Background())
	if err != nil {
		t.Fatalf("failed to move local policy rule: %v", err)
	}
	if state != SetupPolicyRoutingRules {
		t.Fatalf("got: %v, wanted: %v", state, SetupPolicyRoutingRules)
	}

	// inspect ip v4 rules
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}

	rulesByPrio := map[int]*netlink.Rule{}
	for _, rule := range rules {
		rulesByPrio[rule.Priority] = &rule
	}

	if rule, ok := rulesByPrio[-1]; ok {
		t.Fatalf("expected prio 0 rule to no longer exist: %v", rule)
	}
	if _, ok := rulesByPrio[100]; !ok {
		t.Fatalf("expected prio 100 rule to exist")
	}

	// inspect ip v4 rules
	rules, err = netlink.RuleList(netlink.FAMILY_V6)
	if err != nil {
		t.Fatal(err)
	}

	rulesByPrio = map[int]*netlink.Rule{}
	for _, rule := range rules {
		rulesByPrio[rule.Priority] = &rule
	}

	if rule, ok := rulesByPrio[-1]; ok {
		t.Fatalf("expected prio 0 rule to no longer exist: %v", rule)
	}
	if _, ok := rulesByPrio[100]; !ok {
		t.Fatalf("expected prio 100 rule to exist")
	}
}

func TestSetupPolicyRoutingRules(t *testing.T) {
	h := NewHarness(t)
	h.Setup(t)

	dConf := option.DaemonConfig{
		EnableIPv4: true,
		EnableIPv6: true,
	}
	var (
		ipV4Addr = net.ParseIP("192.168.1.10")
		ipV6Addr = net.ParseIP("fc00::a")
	)

	m := Manager{
		conf: &Config{
			DaemonConfig: &dConf,
			HostDev1:     h.HostDev1,
			HostDev2:     h.HostDev2,
		},
		IPv4Addr: ipV4Addr,
		IPv6Addr: ipV6Addr,
	}

	state, err := m.SetupPolicyRoutingRules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state != DetermineNetworking {
		t.Fatalf("got: %v, want: %v", state, DetermineNetworking)
	}

	checkRules := func(family int) {
		rules, err := netlink.RuleList(family)
		if err != nil {
			t.Fatal(err)
		}
		rulesByPrio := map[int]*netlink.Rule{}
		for i := range rules {
			rulesByPrio[rules[i].Priority] = &rules[i]
		}
		if _, ok := rulesByPrio[9]; !ok {
			t.Fatalf("missing to-proxy rule priority 9")
		}
		if _, ok := rulesByPrio[10]; !ok {
			t.Fatalf("missing from-proxy rule priority 10")
		}
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{
			Table: 2004,
		}, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v", routes)
	}
	checkRules(netlink.FAMILY_V4)
	checkRules(netlink.FAMILY_V6)

}
