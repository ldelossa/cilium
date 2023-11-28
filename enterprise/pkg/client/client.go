//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package client

import (
	"github.com/go-openapi/strfmt"

	"github.com/cilium/cilium/enterprise/api/v1/client"
	ossclient "github.com/cilium/cilium/pkg/client"
)

type EnterpriseClient struct {
	*client.CiliumEnterpriseAPI
}

func NewDefaultClient() (*EnterpriseClient, error) {
	rt, err := ossclient.NewRuntime(ossclient.WithBasePath("/v1enterprise"))
	if err != nil {
		return nil, err
	}
	return &EnterpriseClient{client.New(rt, strfmt.Default)}, nil
}
