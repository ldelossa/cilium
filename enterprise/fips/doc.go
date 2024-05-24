//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
// Package fips can be used to enable the usage of FIPs compliant crypto
// algorithms for a binary, with the following steps:
// 1. Import this package somewhere in the target binary's project.
// 2. Set the environment variable GOEXPERIMENT=boringcrypto
// 3. Build your binary with the build tag 'fips'.

package fips
