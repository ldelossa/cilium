// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Finds available schedules that meet the specified criteria. You can search for
// an available schedule no more than 3 months in advance. You must meet the
// minimum required duration of 1,200 hours per year. For example, the minimum
// daily schedule is 4 hours, the minimum weekly schedule is 24 hours, and the
// minimum monthly schedule is 100 hours. After you find a schedule that meets your
// needs, call PurchaseScheduledInstances to purchase Scheduled Instances with
// that schedule.
func (c *Client) DescribeScheduledInstanceAvailability(ctx context.Context, params *DescribeScheduledInstanceAvailabilityInput, optFns ...func(*Options)) (*DescribeScheduledInstanceAvailabilityOutput, error) {
	if params == nil {
		params = &DescribeScheduledInstanceAvailabilityInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeScheduledInstanceAvailability", params, optFns, c.addOperationDescribeScheduledInstanceAvailabilityMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeScheduledInstanceAvailabilityOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Contains the parameters for DescribeScheduledInstanceAvailability.
type DescribeScheduledInstanceAvailabilityInput struct {

	// The time period for the first schedule to start.
	//
	// This member is required.
	FirstSlotStartTimeRange *types.SlotDateTimeRangeRequest

	// The schedule recurrence.
	//
	// This member is required.
	Recurrence *types.ScheduledInstanceRecurrenceRequest

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// The filters.
	//   - availability-zone - The Availability Zone (for example, us-west-2a ).
	//   - instance-type - The instance type (for example, c4.large ).
	//   - platform - The platform ( Linux/UNIX or Windows ).
	Filters []types.Filter

	// The maximum number of results to return in a single call. This value can be
	// between 5 and 300. The default value is 300. To retrieve the remaining results,
	// make another call with the returned NextToken value.
	MaxResults *int32

	// The maximum available duration, in hours. This value must be greater than
	// MinSlotDurationInHours and less than 1,720.
	MaxSlotDurationInHours *int32

	// The minimum available duration, in hours. The minimum required duration is
	// 1,200 hours per year. For example, the minimum daily schedule is 4 hours, the
	// minimum weekly schedule is 24 hours, and the minimum monthly schedule is 100
	// hours.
	MinSlotDurationInHours *int32

	// The token for the next set of results.
	NextToken *string

	noSmithyDocumentSerde
}

// Contains the output of DescribeScheduledInstanceAvailability.
type DescribeScheduledInstanceAvailabilityOutput struct {

	// The token required to retrieve the next set of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Information about the available Scheduled Instances.
	ScheduledInstanceAvailabilitySet []types.ScheduledInstanceAvailability

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeScheduledInstanceAvailabilityMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeScheduledInstanceAvailability{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeScheduledInstanceAvailability{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeScheduledInstanceAvailability"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addOpDescribeScheduledInstanceAvailabilityValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeScheduledInstanceAvailability(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	return nil
}

// DescribeScheduledInstanceAvailabilityAPIClient is a client that implements the
// DescribeScheduledInstanceAvailability operation.
type DescribeScheduledInstanceAvailabilityAPIClient interface {
	DescribeScheduledInstanceAvailability(context.Context, *DescribeScheduledInstanceAvailabilityInput, ...func(*Options)) (*DescribeScheduledInstanceAvailabilityOutput, error)
}

var _ DescribeScheduledInstanceAvailabilityAPIClient = (*Client)(nil)

// DescribeScheduledInstanceAvailabilityPaginatorOptions is the paginator options
// for DescribeScheduledInstanceAvailability
type DescribeScheduledInstanceAvailabilityPaginatorOptions struct {
	// The maximum number of results to return in a single call. This value can be
	// between 5 and 300. The default value is 300. To retrieve the remaining results,
	// make another call with the returned NextToken value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeScheduledInstanceAvailabilityPaginator is a paginator for
// DescribeScheduledInstanceAvailability
type DescribeScheduledInstanceAvailabilityPaginator struct {
	options   DescribeScheduledInstanceAvailabilityPaginatorOptions
	client    DescribeScheduledInstanceAvailabilityAPIClient
	params    *DescribeScheduledInstanceAvailabilityInput
	nextToken *string
	firstPage bool
}

// NewDescribeScheduledInstanceAvailabilityPaginator returns a new
// DescribeScheduledInstanceAvailabilityPaginator
func NewDescribeScheduledInstanceAvailabilityPaginator(client DescribeScheduledInstanceAvailabilityAPIClient, params *DescribeScheduledInstanceAvailabilityInput, optFns ...func(*DescribeScheduledInstanceAvailabilityPaginatorOptions)) *DescribeScheduledInstanceAvailabilityPaginator {
	if params == nil {
		params = &DescribeScheduledInstanceAvailabilityInput{}
	}

	options := DescribeScheduledInstanceAvailabilityPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeScheduledInstanceAvailabilityPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeScheduledInstanceAvailabilityPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next DescribeScheduledInstanceAvailability page.
func (p *DescribeScheduledInstanceAvailabilityPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeScheduledInstanceAvailabilityOutput, error) {
	if !p.HasMorePages() {
		return nil, fmt.Errorf("no more pages available")
	}

	params := *p.params
	params.NextToken = p.nextToken

	var limit *int32
	if p.options.Limit > 0 {
		limit = &p.options.Limit
	}
	params.MaxResults = limit

	result, err := p.client.DescribeScheduledInstanceAvailability(ctx, &params, optFns...)
	if err != nil {
		return nil, err
	}
	p.firstPage = false

	prevToken := p.nextToken
	p.nextToken = result.NextToken

	if p.options.StopOnDuplicateToken &&
		prevToken != nil &&
		p.nextToken != nil &&
		*prevToken == *p.nextToken {
		p.nextToken = nil
	}

	return result, nil
}

func newServiceMetadataMiddleware_opDescribeScheduledInstanceAvailability(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeScheduledInstanceAvailability",
	}
}
