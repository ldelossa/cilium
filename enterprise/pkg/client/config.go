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
	"github.com/cilium/cilium/enterprise/api/v1/client/daemon"
	"github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/pkg/api"
)

// EnterpriseConfig returns the current configuration of enterprise-only options
func (c *EnterpriseClient) EnterpriseConfig() (*models.EnterpriseDaemonConfiguration, error) {
	params := daemon.NewGetConfigParamsWithTimeout(api.ClientTimeout)

	resp, err := c.Daemon.GetConfig(params)
	if err != nil {
		return nil, err
	}
	return resp.Payload, nil
}
