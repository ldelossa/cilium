//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ipcache

// InjectCEMap allows to override the default ipcache map interface injected
// through hive to possibly mutate the key/value pair to support additional
// enterprise features (e.g., mixed routing mode). This method is intended to
// be executed through an Invoke function.
func InjectCEMap(l *BPFListener, override Map) {
	l.bpfMap = override
}
