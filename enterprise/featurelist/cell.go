//nolint:goheader
// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package featurelist

import (
	"github.com/cilium/hive/cell"
)

// EnterpriseFeatures provides a declaration of features (both OSS and Enterprise) as they
// are currently supported in Cilium for CE customers:
//
// See feature maturity matrix here:
//
//	https://docs.google.com/spreadsheets/d/1OjcFPEG9J2pJDaIsIyIXyrEBy2wT-PUiMM3PbzpoO40/
var Cell = cell.Group()
