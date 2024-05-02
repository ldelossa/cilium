//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package api

import (
	"net/http"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	enterpriseserver "github.com/cilium/cilium/enterprise/api/v1/server"
	"github.com/cilium/cilium/enterprise/api/v1/server/restapi"
)

var Cell = cell.Module(
	"enterprise-api",
	"Implements the Cilium Enterprise API",

	cell.Provide(configureEnterpriseAPI),
	cell.Provide(newHealthzHandler),
)

type enterpriseAPIIn struct {
	cell.In

	API  *restapi.CiliumEnterpriseAPIAPI
	Spec *enterpriseserver.Spec
}

type enterpriseAPIOut struct {
	cell.Out

	Middleware middleware.Builder `name:"cilium-api-middleware"`
}

// configureEnterpriseAPI injects the enterprise API into the Cilium API socket
// by registering a custom middleware with Hive. The custom middleware redirects
// all requests which match the Enterprise API basepath (i.e. /v1enterprise) to
// the enterprise API handler. All other requests are passed up to the next
// handler, which is the (OSS) Cilium API handler.
func configureEnterpriseAPI(params enterpriseAPIIn) enterpriseAPIOut {
	ceeHandler := params.API.Serve(nil)
	basePath := params.Spec.BasePath()

	return enterpriseAPIOut{
		Middleware: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, basePath) {
					ceeHandler.ServeHTTP(w, r)
					return
				}
				next.ServeHTTP(w, r)
			})
		},
	}
}
