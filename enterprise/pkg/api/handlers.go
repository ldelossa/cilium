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
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/enterprise/api/v1/server/restapi"
	"github.com/cilium/cilium/enterprise/api/v1/server/restapi/network"
)

// Handler implements Handle() for the given parameter type.
// It allows expressing the API handlers simply as a function of form
// `func(p ParamType) middleware.Responder`.
type Handler[Params any] struct {
	handler func(p Params) middleware.Responder
}

func (h *Handler[Params]) Handle(p Params) middleware.Responder {
	return h.handler(p)
}

func NewHandler[Params any](handler func(p Params) middleware.Responder) *Handler[Params] {
	return &Handler[Params]{handler: handler}
}

// newHealthzHandler returns a handler for the /v1enterprise/healthz endpoint.
func newHealthzHandler() restapi.GetHealthzHandler {
	return NewHandler[restapi.GetHealthzParams](func(p restapi.GetHealthzParams) middleware.Responder {
		return restapi.NewGetHealthzOK()
	})
}

// newNetworkHandler returns a default handler for the /network/attachments endpoint
func newNetworkHandler() network.GetNetworkAttachmentHandler {
	return NewHandler[network.GetNetworkAttachmentParams](func(p network.GetNetworkAttachmentParams) middleware.Responder {
		return network.NewGetNetworkAttachmentDisabled()
	})
}
