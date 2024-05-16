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

// Describes one or more of your Capacity Reservations. The results describe only
// the Capacity Reservations in the Amazon Web Services Region that you're
// currently using.
func (c *Client) DescribeCapacityReservations(ctx context.Context, params *DescribeCapacityReservationsInput, optFns ...func(*Options)) (*DescribeCapacityReservationsOutput, error) {
	if params == nil {
		params = &DescribeCapacityReservationsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeCapacityReservations", params, optFns, c.addOperationDescribeCapacityReservationsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeCapacityReservationsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeCapacityReservationsInput struct {

	// The ID of the Capacity Reservation.
	CapacityReservationIds []string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// One or more filters.
	//
	//   - instance-type - The type of instance for which the Capacity Reservation
	//   reserves capacity.
	//
	//   - owner-id - The ID of the Amazon Web Services account that owns the Capacity
	//   Reservation.
	//
	//   - instance-platform - The type of operating system for which the Capacity
	//   Reservation reserves capacity.
	//
	//   - availability-zone - The Availability Zone of the Capacity Reservation.
	//
	//   - tenancy - Indicates the tenancy of the Capacity Reservation. A Capacity
	//   Reservation can have one of the following tenancy settings:
	//
	//   - default - The Capacity Reservation is created on hardware that is shared
	//   with other Amazon Web Services accounts.
	//
	//   - dedicated - The Capacity Reservation is created on single-tenant hardware
	//   that is dedicated to a single Amazon Web Services account.
	//
	//   - outpost-arn - The Amazon Resource Name (ARN) of the Outpost on which the
	//   Capacity Reservation was created.
	//
	//   - state - The current state of the Capacity Reservation. A Capacity
	//   Reservation can be in one of the following states:
	//
	//   - active - The Capacity Reservation is active and the capacity is available
	//   for your use.
	//
	//   - expired - The Capacity Reservation expired automatically at the date and
	//   time specified in your request. The reserved capacity is no longer available for
	//   your use.
	//
	//   - cancelled - The Capacity Reservation was cancelled. The reserved capacity is
	//   no longer available for your use.
	//
	//   - pending - The Capacity Reservation request was successful but the capacity
	//   provisioning is still pending.
	//
	//   - failed - The Capacity Reservation request has failed. A request might fail
	//   due to invalid request parameters, capacity constraints, or instance limit
	//   constraints. Failed requests are retained for 60 minutes.
	//
	//   - start-date - The date and time at which the Capacity Reservation was started.
	//
	//   - end-date - The date and time at which the Capacity Reservation expires. When
	//   a Capacity Reservation expires, the reserved capacity is released and you can no
	//   longer launch instances into it. The Capacity Reservation's state changes to
	//   expired when it reaches its end date and time.
	//
	//   - end-date-type - Indicates the way in which the Capacity Reservation ends. A
	//   Capacity Reservation can have one of the following end types:
	//
	//   - unlimited - The Capacity Reservation remains active until you explicitly
	//   cancel it.
	//
	//   - limited - The Capacity Reservation expires automatically at a specified date
	//   and time.
	//
	//   - instance-match-criteria - Indicates the type of instance launches that the
	//   Capacity Reservation accepts. The options include:
	//
	//   - open - The Capacity Reservation accepts all instances that have matching
	//   attributes (instance type, platform, and Availability Zone). Instances that have
	//   matching attributes launch into the Capacity Reservation automatically without
	//   specifying any additional parameters.
	//
	//   - targeted - The Capacity Reservation only accepts instances that have
	//   matching attributes (instance type, platform, and Availability Zone), and
	//   explicitly target the Capacity Reservation. This ensures that only permitted
	//   instances can use the reserved capacity.
	//
	//   - placement-group-arn - The ARN of the cluster placement group in which the
	//   Capacity Reservation was created.
	Filters []types.Filter

	// The maximum number of items to return for this request. To get the next page of
	// items, make another request with the token returned in the output. For more
	// information, see [Pagination].
	//
	// [Pagination]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination
	MaxResults *int32

	// The token to use to retrieve the next page of results.
	NextToken *string

	noSmithyDocumentSerde
}

type DescribeCapacityReservationsOutput struct {

	// Information about the Capacity Reservations.
	CapacityReservations []types.CapacityReservation

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeCapacityReservationsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeCapacityReservations{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeCapacityReservations{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeCapacityReservations"); err != nil {
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeCapacityReservations(options.Region), middleware.Before); err != nil {
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

// DescribeCapacityReservationsAPIClient is a client that implements the
// DescribeCapacityReservations operation.
type DescribeCapacityReservationsAPIClient interface {
	DescribeCapacityReservations(context.Context, *DescribeCapacityReservationsInput, ...func(*Options)) (*DescribeCapacityReservationsOutput, error)
}

var _ DescribeCapacityReservationsAPIClient = (*Client)(nil)

// DescribeCapacityReservationsPaginatorOptions is the paginator options for
// DescribeCapacityReservations
type DescribeCapacityReservationsPaginatorOptions struct {
	// The maximum number of items to return for this request. To get the next page of
	// items, make another request with the token returned in the output. For more
	// information, see [Pagination].
	//
	// [Pagination]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeCapacityReservationsPaginator is a paginator for
// DescribeCapacityReservations
type DescribeCapacityReservationsPaginator struct {
	options   DescribeCapacityReservationsPaginatorOptions
	client    DescribeCapacityReservationsAPIClient
	params    *DescribeCapacityReservationsInput
	nextToken *string
	firstPage bool
}

// NewDescribeCapacityReservationsPaginator returns a new
// DescribeCapacityReservationsPaginator
func NewDescribeCapacityReservationsPaginator(client DescribeCapacityReservationsAPIClient, params *DescribeCapacityReservationsInput, optFns ...func(*DescribeCapacityReservationsPaginatorOptions)) *DescribeCapacityReservationsPaginator {
	if params == nil {
		params = &DescribeCapacityReservationsInput{}
	}

	options := DescribeCapacityReservationsPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeCapacityReservationsPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeCapacityReservationsPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next DescribeCapacityReservations page.
func (p *DescribeCapacityReservationsPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeCapacityReservationsOutput, error) {
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

	result, err := p.client.DescribeCapacityReservations(ctx, &params, optFns...)
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

func newServiceMetadataMiddleware_opDescribeCapacityReservations(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeCapacityReservations",
	}
}
