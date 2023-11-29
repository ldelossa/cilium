//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package manager

// CEIPSetManager aliases the private ipsetManager interface.
type CEIPSetManager = ipsetManager

// InjectCEIPSetManager allows to override the default ipsetManager injected
// through hive, to support additional enterprise features (e.g., filter ipset
// entries for mixed routing mode). This method is intended to be executed
// through an Invoke function before starting the NodeManager subsystem.
func InjectCEIPSetManager(mgr NodeManager, ipsetter CEIPSetManager) {
	impl, ok := mgr.(*manager)
	if !ok {
		return
	}

	impl.ipsetMgr = ipsetter
}
