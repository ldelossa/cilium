//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package labels

const (
	IdNameCiliumMesh = "com.isovalent.cilium-mesh"
)

var (
	// LabelCiliumMesh is a label used to distinguish CiliumMesh Endpoints.
	// This label will have its source as "unspec" and not "reserved" for the
	// moment since the daemon API rejects endpoint creation that have
	// "reserved" labels
	LabelCiliumMesh = Labels{IdNameCiliumMesh: NewLabel(IdNameCiliumMesh, "", LabelSourceUnspec)}
)
