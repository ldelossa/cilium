// Code generated by go-swagger; DO NOT EDIT.

// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package restapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// GetHealthzHandlerFunc turns a function with the right signature into a get healthz handler
type GetHealthzHandlerFunc func(GetHealthzParams) middleware.Responder

// Handle executing the request and returning a response
func (fn GetHealthzHandlerFunc) Handle(params GetHealthzParams) middleware.Responder {
	return fn(params)
}

// GetHealthzHandler interface for that can handle valid get healthz params
type GetHealthzHandler interface {
	Handle(GetHealthzParams) middleware.Responder
}

// NewGetHealthz creates a new http.Handler for the get healthz operation
func NewGetHealthz(ctx *middleware.Context, handler GetHealthzHandler) *GetHealthz {
	return &GetHealthz{Context: ctx, Handler: handler}
}

/*
	GetHealthz swagger:route GET /healthz getHealthz

Retrieve Cilium Enterprise health
*/
type GetHealthz struct {
	Context *middleware.Context
	Handler GetHealthzHandler
}

func (o *GetHealthz) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewGetHealthzParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}
