//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dnsresolver

import "golang.org/x/exp/slices"

// status is a type that represents the internal status of a manager. It
// contains a map of IsovalentFQDNGroup names to their respective list of
// FQDNs. This type extends the basic map type with some useful methods to
// reconcile the manager status after a IsovalentFQDNGroup related event.
type status map[string][]string

// deepCopy returns a deep copy of the status map.
func (s status) deepCopy() status {
	if s == nil {
		return nil
	}
	cp := make(status, len(s))
	for key, values := range s {
		cp[key] = slices.Clone(values)
	}
	return cp
}

// diff returns the diff between two manager statuses.
// The diff is composed by two slices of strings:
//   - the first one contains the new FQDNs, that is, all the FQDNs that are present
//     in the new status but not in the current one.
//   - the second one contains the stale FQDNs, that is, all the FQDNs that are present
//     in the current status but not in the new one.
func (s status) diff(new status) ([]string, []string) {
	curFQDNs, newFQDNs := fqdns(s), fqdns(new)
	return diff(newFQDNs, curFQDNs), diff(curFQDNs, newFQDNs)
}

// fqdns returns a set containing all the unique fqdns in the input status.
func fqdns(s status) map[string]struct{} {
	fqdns := make(map[string]struct{})
	for _, set := range s {
		for _, fqdn := range set {
			fqdns[fqdn] = struct{}{}
		}
	}
	return fqdns
}

// diff returns the differences between set a and set b.
func diff(a, b map[string]struct{}) []string {
	var values []string
	for key := range a {
		if _, ok := b[key]; !ok {
			values = append(values, key)
		}
	}
	return values
}
