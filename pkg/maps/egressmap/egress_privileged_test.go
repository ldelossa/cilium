// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build privileged_tests

package egressmap

import (
	"net"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/tuple"
)

// Hook up gocheck into the "go test" runner.
type EgressMapTestSuite struct{}

var _ = Suite(&EgressMapTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (k *EgressMapTestSuite) SetUpSuite(c *C) {
	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (k *EgressMapTestSuite) TestEgressMap(c *C) {
	err := initEgressPolicyMap("test_"+PolicyMapName, true)
	c.Assert(err, IsNil)
	defer EgressPolicyMap.Unpin()

	err = initEgressCtMap("test_"+CtMapName, true)
	c.Assert(err, IsNil)
	defer EgressCtMap.Unpin()

	sourceIP1 := net.ParseIP("1.1.1.1")
	sourceIP2 := net.ParseIP("1.1.1.2")

	_, destCIDR1, err := net.ParseCIDR("2.2.1.0/24")
	c.Assert(err, IsNil)
	_, destCIDR2, err := net.ParseCIDR("2.2.2.0/24")
	c.Assert(err, IsNil)

	destIP1 := net.ParseIP("2.2.1.1")
	destIP2 := net.ParseIP("2.2.2.1")

	egressIP1 := net.ParseIP("3.3.3.1")
	egressIP2 := net.ParseIP("3.3.3.2")

	gatewayIP1 := net.ParseIP("4.4.4.1")
	gatewayIP2 := net.ParseIP("4.4.4.2")

	randomIP := net.ParseIP("10.20.30.40")

	// This will create 2 policies, respectively with 2 and 1 egress GWs:
	//
	// Source IP   Destination CIDR   Egress IP   Gateway
	// 1.1.1.1     2.2.1.0/24         3.3.3.1     0 => 4.4.4.1
	//                                            1 => 4.4.4.2
	// 1.1.1.2     2.2.2.0/24         3.3.3.2     0 => 4.4.4.1

	err = ApplyEgressPolicy(sourceIP1, *destCIDR1, egressIP1, []net.IP{gatewayIP1, gatewayIP2}, []net.IP{gatewayIP1, gatewayIP2})
	c.Assert(err, IsNil)

	defer RemoveEgressPolicy(sourceIP1, *destCIDR1)

	err = ApplyEgressPolicy(sourceIP2, *destCIDR2, egressIP2, []net.IP{gatewayIP1}, []net.IP{gatewayIP1})
	c.Assert(err, IsNil)

	defer RemoveEgressPolicy(sourceIP2, *destCIDR2)

	val, err := EgressPolicyMap.Lookup(sourceIP1, *destCIDR1)
	c.Assert(err, IsNil)

	c.Assert(val.Size, Equals, uint32(2))
	c.Assert(val.EgressIP.IP().Equal(egressIP1), Equals, true)
	c.Assert(val.GatewayIPs[0].IP().Equal(gatewayIP1), Equals, true)
	c.Assert(val.GatewayIPs[1].IP().Equal(gatewayIP2), Equals, true)

	val, err = EgressPolicyMap.Lookup(sourceIP2, *destCIDR2)
	c.Assert(err, IsNil)

	c.Assert(val.Size, Equals, uint32(1))
	c.Assert(val.EgressIP.IP().Equal(egressIP2), Equals, true)
	c.Assert(val.GatewayIPs[0].IP().Equal(gatewayIP1), Equals, true)

	// Addin a policy with too many gateways should result in an error
	gatewayIPs := make([]net.IP, MaxGatewayNodes+1)
	err = ApplyEgressPolicy(sourceIP1, *destCIDR1, egressIP1, gatewayIPs, gatewayIPs)
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, "cannot apply egress policy: too many gateways")

	// Create 4 CT entries in the egress CT map
	// ctKey1 is related to the first policy (first gateway node)
	ctKey1 := addEgressCtEntry(c, sourceIP1, destIP1, 80, gatewayIP1)
	// ctKey2 is related to the first policy (second gateway node)
	ctKey2 := addEgressCtEntry(c, sourceIP1, destIP1, 81, gatewayIP2)
	// ctKey3 is related to the second policy
	ctKey3 := addEgressCtEntry(c, sourceIP2, destIP2, 80, gatewayIP1)
	// ctKey4 is unrelated to any policy
	ctKey4 := addEgressCtEntry(c, randomIP, randomIP, 1234, randomIP)

	// Update the first policy:
	//
	// - remove gatewayIP1 from the list of active gateways (by applying a
	//   new policy with just gatewayIP2)
	// - remove gatewayIP1 also from the list of healthy gateways
	err = ApplyEgressPolicy(sourceIP1, *destCIDR1, egressIP1, []net.IP{gatewayIP2}, []net.IP{gatewayIP2})
	c.Assert(err, IsNil)

	// The first CT entry (first policy, gatewayIP1) should get removed
	assertCtKeyDoesntExist(c, ctKey1)

	// While the second CT entry (first policy, gatewayIP2) should still be there
	assertCtKeyExists(c, ctKey2)

	// as well as the other (unrelated) ones
	assertCtKeyExists(c, ctKey3)
	assertCtKeyExists(c, ctKey4)

	// Update the first policy:
	//
	// - change the active gateway from gatewayIP2 -> gatewayIP1
	//-  keep gatewayIP2 in the list of healthy gateways
	err = ApplyEgressPolicy(sourceIP1, *destCIDR1, egressIP1, []net.IP{gatewayIP1}, []net.IP{gatewayIP1, gatewayIP2})
	c.Assert(err, IsNil)

	// The second CT entry (first policy, gatewayIP2) should still be there
	assertCtKeyExists(c, ctKey2)

	// as well as the other (unrelated) ones
	assertCtKeyExists(c, ctKey3)
	assertCtKeyExists(c, ctKey4)

	// Update the first policy:
	//
	//-  Remove gatewayIP2 from the list of healthy gateways
	err = ApplyEgressPolicy(sourceIP1, *destCIDR1, egressIP1, []net.IP{gatewayIP1}, []net.IP{gatewayIP1})
	c.Assert(err, IsNil)

	// The second CT entry (first policy, gatewayIP2) should now get removed
	assertCtKeyDoesntExist(c, ctKey2)

	// while the other unrelated ones should still be there
	assertCtKeyExists(c, ctKey3)
	assertCtKeyExists(c, ctKey4)

	// Remove the second policy
	err = RemoveEgressPolicy(sourceIP2, *destCIDR2)
	c.Assert(err, IsNil)

	// The third CT entry (second policy) should now get removed
	assertCtKeyDoesntExist(c, ctKey3)

	//while the other unrelated one should still be there
	assertCtKeyExists(c, ctKey4)
}

func addEgressCtEntry(c *C, sourceIP, destIP net.IP, dstPort uint16, gatewayIP net.IP) *EgressCtKey4 {
	ctKey := EgressCtKey4{
		tuple.TupleKey4{
			SourcePort: 1111,
			DestPort:   dstPort,
			NextHeader: 6,
		},
	}
	copy(ctKey.SourceAddr[:], sourceIP.To4())
	copy(ctKey.DestAddr[:], destIP.To4())

	ctVal := EgressCtVal4{}
	copy(ctVal.Gateway[:], gatewayIP.To4())

	err := EgressCtMap.Update(&ctKey, &ctVal, 0)
	c.Assert(err, IsNil)

	return &ctKey
}

func assertCtKeyExists(c *C, ctKey *EgressCtKey4) {
	ctValTmp := EgressCtVal4{}
	err := EgressCtMap.Lookup(ctKey, &ctValTmp)
	c.Assert(err, IsNil)
}

func assertCtKeyDoesntExist(c *C, ctKey *EgressCtKey4) {
	ctValTmp := EgressCtVal4{}
	err := EgressCtMap.Lookup(ctKey, &ctValTmp)
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, "lookup: key does not exist")
}
