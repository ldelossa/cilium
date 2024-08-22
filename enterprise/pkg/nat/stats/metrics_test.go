//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package stats

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/nat/stats"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/stretchr/testify/assert"

	"k8s.io/apimachinery/pkg/util/sets"
)

func makeTestIPs(family string, n int) (egressIP string, endpointIP string) {
	eip := fmt.Sprintf("10.0.0.%d", n)
	epip := fmt.Sprintf("999.0.0.%d", n)
	if family == "ipv6" {
		eip = fmt.Sprintf("::%d", n)
		epip = fmt.Sprintf("::1%d", n)
	}
	return eip, epip
}

func TestTopkMetrics(t *testing.T) {
	ms := &fakeMetrics{
		m: map[stats.NatMapStats]int{},
	}
	h := hive.New(
		cell.Provide(newTables, newTopkMetrics),
		cell.Provide(func(jg job.Registry, rwt statedb.RWTable[stats.NatMapStats]) (job.Group, metricsActions,
			stats.Config, statedb.Table[stats.NatMapStats]) {
			return jg.NewGroup(nil), ms, stats.Config{
				NatMapStatKStoredEntries: 5,
				NATMapStatInterval:       time.Duration(0),
			}, rwt
		}),
		cell.Invoke(func(tk *topkMetrics, rwt statedb.RWTable[stats.NatMapStats]) {
			setTable := func(family string, from, to int) {
				tx := tk.db.WriteTxn(rwt)
				defer tx.Abort()
				iter := rwt.All(tx)
				for entry, _, ok := iter.Next(); ok; entry, _, ok = iter.Next() {
					if entry.Type == family {
						_, _, err := rwt.Delete(tx, entry)
						assert.NoError(t, err)
					}
				}
				for i := from; i < to; i++ {
					eip, epip := makeTestIPs(family, i+1)
					_, _, err := rwt.Insert(tx, stats.NatMapStats{
						Type:       family,
						EgressIP:   eip,
						EndpointIP: epip,
						RemotePort: uint16(i + 1),
						Count:      i + 1,
						Nth:        to - i,
					})
					assert.NoError(t, err)
				}
				tx.Commit()
			}

			updateAndAssertMetrics := func(family string, start, end, expectDeleted int) {
				tx := tk.db.ReadTxn()
				iter := tk.statsTable.All(tx)
				err := tk.update(iter)
				assert.NoError(t, err)
				assert.Equal(t, expectDeleted, tk.lastDeleted)
				emitted := sets.New[uint16]()
				for k := range ms.m {
					if k.Type != family {
						continue
					}
					assert.Equal(t, k.Count, int(k.RemotePort))
					eip, epip := makeTestIPs(family, k.Count)
					assert.Equal(t, k.EndpointIP, epip)
					assert.Equal(t, k.EgressIP, eip)
					emitted.Insert(uint16(k.Count))
				}
				assert.Len(t, emitted, end-start)
				for i := uint16(start) + 1; i <= uint16(end); i++ {
					assert.Contains(t, emitted, i)
				}
			}

			// Initially set to a range of one through ten and check.
			setTable("ipv4", 0, 10)
			setTable("ipv6", 50, 60)
			updateAndAssertMetrics("ipv4", 0, 10, 0)
			updateAndAssertMetrics("ipv6", 50, 60, 0)

			// New range should overlap old one but should force deletes.
			setTable("ipv4", 5, 15)
			updateAndAssertMetrics("ipv4", 5, 15, 5)
			updateAndAssertMetrics("ipv6", 50, 60, 0) // no change on ipv6.

			// Table did not change, thus there should be no deletes.
			setTable("ipv6", 50, 60)
			updateAndAssertMetrics("ipv4", 5, 15, 0)
			updateAndAssertMetrics("ipv6", 50, 60, 0) // no change on ipv6.

			// In this case, all ten existing entries expect to be deleted as our
			// new range is disjoint from the previous one ([5,15] -> [100,120])
			setTable("ipv4", 100, 120)
			updateAndAssertMetrics("ipv4", 100, 120, 10)
			updateAndAssertMetrics("ipv6", 50, 60, 0) // no change on ipv6.

			// Set table with ipv6 entries and assert that all previous ip6 tuples
			// got removed (previously there where 10).
			setTable("ipv6", 100, 120)
			updateAndAssertMetrics("ipv6", 100, 120, 10)
			updateAndAssertMetrics("ipv4", 100, 120, 0) // no change on ipv4.

			setTable("ipv6", 105, 125)
			updateAndAssertMetrics("ipv6", 105, 125, 5)
			updateAndAssertMetrics("ipv4", 100, 120, 0) // no change on ipv4.
		}),
	)
	assert.NoError(t, h.Populate(hivetest.Logger(t)))
}

type fakeMetrics struct {
	m map[stats.NatMapStats]int
}

func (f *fakeMetrics) deleteTopkMetric(entry stats.NatMapStats) {
	delete(f.m, entry)
}

func (f *fakeMetrics) upsertTopkMetric(entry stats.NatMapStats) {
	f.m[entry] = entry.Count
}

func (f *fakeMetrics) isEnabled() bool {
	return true
}

func newTables(db *statedb.DB) (statedb.RWTable[stats.NatMapStats], error) {
	statusTable, err := statedb.NewTable(stats.TableName, stats.Index)
	if err != nil {
		return nil, err
	}
	if err := db.RegisterTable(statusTable); err != nil {
		return nil, err
	}
	return statusTable, nil
}
