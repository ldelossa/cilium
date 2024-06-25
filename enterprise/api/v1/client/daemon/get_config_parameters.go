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

package daemon

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewGetConfigParams creates a new GetConfigParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetConfigParams() *GetConfigParams {
	return &GetConfigParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetConfigParamsWithTimeout creates a new GetConfigParams object
// with the ability to set a timeout on a request.
func NewGetConfigParamsWithTimeout(timeout time.Duration) *GetConfigParams {
	return &GetConfigParams{
		timeout: timeout,
	}
}

// NewGetConfigParamsWithContext creates a new GetConfigParams object
// with the ability to set a context for a request.
func NewGetConfigParamsWithContext(ctx context.Context) *GetConfigParams {
	return &GetConfigParams{
		Context: ctx,
	}
}

// NewGetConfigParamsWithHTTPClient creates a new GetConfigParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetConfigParamsWithHTTPClient(client *http.Client) *GetConfigParams {
	return &GetConfigParams{
		HTTPClient: client,
	}
}

/*
GetConfigParams contains all the parameters to send to the API endpoint

	for the get config operation.

	Typically these are written to a http.Request.
*/
type GetConfigParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get config params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetConfigParams) WithDefaults() *GetConfigParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get config params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetConfigParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get config params
func (o *GetConfigParams) WithTimeout(timeout time.Duration) *GetConfigParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get config params
func (o *GetConfigParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get config params
func (o *GetConfigParams) WithContext(ctx context.Context) *GetConfigParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get config params
func (o *GetConfigParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get config params
func (o *GetConfigParams) WithHTTPClient(client *http.Client) *GetConfigParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get config params
func (o *GetConfigParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetConfigParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
