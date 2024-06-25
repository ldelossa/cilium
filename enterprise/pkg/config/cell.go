// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/api/v1/models"
	"github.com/cilium/cilium/enterprise/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/enterprise/pkg/api"
	"github.com/cilium/cilium/enterprise/pkg/multinetwork"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var Cell = cell.Module(
	"enterprise-config",
	"Determines which enterprise-only configuration options are enabled",

	cell.Provide(newConfigAPIHandler),
)

type GetConfigParams struct {
	cell.In

	Logger logrus.FieldLogger
	Cfg    multinetwork.Config
}

func newConfigAPIHandler(p GetConfigParams) daemon.GetConfigHandler {
	return api.NewHandler[daemon.GetConfigParams](func(rp daemon.GetConfigParams) middleware.Responder {
		p.Logger.WithField(logfields.Params, logfields.Repr(rp)).Debug("GET /v1enterprise/config request")
		cfg := &models.EnterpriseDaemonConfiguration{
			MultiNetwork: p.Cfg.EnableMultiNetwork,
		}
		return daemon.NewGetConfigOK().WithPayload(cfg)

	})
}
