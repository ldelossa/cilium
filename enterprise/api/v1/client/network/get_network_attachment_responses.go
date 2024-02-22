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

package network

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cilium/cilium/enterprise/api/v1/models"
)

// GetNetworkAttachmentReader is a Reader for the GetNetworkAttachment structure.
type GetNetworkAttachmentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetNetworkAttachmentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetNetworkAttachmentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewGetNetworkAttachmentFailure()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 501:
		result := NewGetNetworkAttachmentDisabled()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetNetworkAttachmentOK creates a GetNetworkAttachmentOK with default headers values
func NewGetNetworkAttachmentOK() *GetNetworkAttachmentOK {
	return &GetNetworkAttachmentOK{}
}

/*
GetNetworkAttachmentOK describes a response with status code 200, with default header values.

Success
*/
type GetNetworkAttachmentOK struct {
	Payload *models.NetworkAttachmentList
}

// IsSuccess returns true when this get network attachment o k response has a 2xx status code
func (o *GetNetworkAttachmentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get network attachment o k response has a 3xx status code
func (o *GetNetworkAttachmentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get network attachment o k response has a 4xx status code
func (o *GetNetworkAttachmentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get network attachment o k response has a 5xx status code
func (o *GetNetworkAttachmentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get network attachment o k response a status code equal to that given
func (o *GetNetworkAttachmentOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetNetworkAttachmentOK) Error() string {
	return fmt.Sprintf("[GET /network/attachment][%d] getNetworkAttachmentOK  %+v", 200, o.Payload)
}

func (o *GetNetworkAttachmentOK) String() string {
	return fmt.Sprintf("[GET /network/attachment][%d] getNetworkAttachmentOK  %+v", 200, o.Payload)
}

func (o *GetNetworkAttachmentOK) GetPayload() *models.NetworkAttachmentList {
	return o.Payload
}

func (o *GetNetworkAttachmentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.NetworkAttachmentList)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetNetworkAttachmentFailure creates a GetNetworkAttachmentFailure with default headers values
func NewGetNetworkAttachmentFailure() *GetNetworkAttachmentFailure {
	return &GetNetworkAttachmentFailure{}
}

/*
GetNetworkAttachmentFailure describes a response with status code 500, with default header values.

Network attachment error
*/
type GetNetworkAttachmentFailure struct {
	Payload models.Error
}

// IsSuccess returns true when this get network attachment failure response has a 2xx status code
func (o *GetNetworkAttachmentFailure) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get network attachment failure response has a 3xx status code
func (o *GetNetworkAttachmentFailure) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get network attachment failure response has a 4xx status code
func (o *GetNetworkAttachmentFailure) IsClientError() bool {
	return false
}

// IsServerError returns true when this get network attachment failure response has a 5xx status code
func (o *GetNetworkAttachmentFailure) IsServerError() bool {
	return true
}

// IsCode returns true when this get network attachment failure response a status code equal to that given
func (o *GetNetworkAttachmentFailure) IsCode(code int) bool {
	return code == 500
}

func (o *GetNetworkAttachmentFailure) Error() string {
	return fmt.Sprintf("[GET /network/attachment][%d] getNetworkAttachmentFailure  %+v", 500, o.Payload)
}

func (o *GetNetworkAttachmentFailure) String() string {
	return fmt.Sprintf("[GET /network/attachment][%d] getNetworkAttachmentFailure  %+v", 500, o.Payload)
}

func (o *GetNetworkAttachmentFailure) GetPayload() models.Error {
	return o.Payload
}

func (o *GetNetworkAttachmentFailure) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetNetworkAttachmentDisabled creates a GetNetworkAttachmentDisabled with default headers values
func NewGetNetworkAttachmentDisabled() *GetNetworkAttachmentDisabled {
	return &GetNetworkAttachmentDisabled{}
}

/*
GetNetworkAttachmentDisabled describes a response with status code 501, with default header values.

Network attachment feature is disabled
*/
type GetNetworkAttachmentDisabled struct {
}

// IsSuccess returns true when this get network attachment disabled response has a 2xx status code
func (o *GetNetworkAttachmentDisabled) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get network attachment disabled response has a 3xx status code
func (o *GetNetworkAttachmentDisabled) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get network attachment disabled response has a 4xx status code
func (o *GetNetworkAttachmentDisabled) IsClientError() bool {
	return false
}

// IsServerError returns true when this get network attachment disabled response has a 5xx status code
func (o *GetNetworkAttachmentDisabled) IsServerError() bool {
	return true
}

// IsCode returns true when this get network attachment disabled response a status code equal to that given
func (o *GetNetworkAttachmentDisabled) IsCode(code int) bool {
	return code == 501
}

func (o *GetNetworkAttachmentDisabled) Error() string {
	return fmt.Sprintf("[GET /network/attachment][%d] getNetworkAttachmentDisabled ", 501)
}

func (o *GetNetworkAttachmentDisabled) String() string {
	return fmt.Sprintf("[GET /network/attachment][%d] getNetworkAttachmentDisabled ", 501)
}

func (o *GetNetworkAttachmentDisabled) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}