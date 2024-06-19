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

// Describes the Dedicated Host reservations that are available to purchase.
//
// The results describe all of the Dedicated Host reservation offerings, including
// offerings that might not match the instance family and Region of your Dedicated
// Hosts. When purchasing an offering, ensure that the instance family and Region
// of the offering matches that of the Dedicated Hosts with which it is to be
// associated. For more information about supported instance types, see [Dedicated Hosts]in the
// Amazon EC2 User Guide.
//
// [Dedicated Hosts]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/dedicated-hosts-overview.html
func (c *Client) DescribeHostReservationOfferings(ctx context.Context, params *DescribeHostReservationOfferingsInput, optFns ...func(*Options)) (*DescribeHostReservationOfferingsOutput, error) {
	if params == nil {
		params = &DescribeHostReservationOfferingsInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeHostReservationOfferings", params, optFns, c.addOperationDescribeHostReservationOfferingsMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeHostReservationOfferingsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeHostReservationOfferingsInput struct {

	// The filters.
	//
	//   - instance-family - The instance family of the offering (for example, m4 ).
	//
	//   - payment-option - The payment option ( NoUpfront | PartialUpfront |
	//   AllUpfront ).
	Filter []types.Filter

	// This is the maximum duration of the reservation to purchase, specified in
	// seconds. Reservations are available in one-year and three-year terms. The number
	// of seconds specified must be the number of seconds in a year (365x24x60x60)
	// times one of the supported durations (1 or 3). For example, specify 94608000 for
	// three years.
	MaxDuration *int32

	// The maximum number of results to return for the request in a single page. The
	// remaining results can be seen by sending another request with the returned
	// nextToken value. This value can be between 5 and 500. If maxResults is given a
	// larger value than 500, you receive an error.
	MaxResults *int32

	// This is the minimum duration of the reservation you'd like to purchase,
	// specified in seconds. Reservations are available in one-year and three-year
	// terms. The number of seconds specified must be the number of seconds in a year
	// (365x24x60x60) times one of the supported durations (1 or 3). For example,
	// specify 31536000 for one year.
	MinDuration *int32

	// The token to use to retrieve the next page of results.
	NextToken *string

	// The ID of the reservation offering.
	OfferingId *string

	noSmithyDocumentSerde
}

type DescribeHostReservationOfferingsOutput struct {

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Information about the offerings.
	OfferingSet []types.HostOffering

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeHostReservationOfferingsMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeHostReservationOfferings{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeHostReservationOfferings{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeHostReservationOfferings"); err != nil {
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
	if err = addTimeOffsetBuild(stack, c); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeHostReservationOfferings(options.Region), middleware.Before); err != nil {
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

// DescribeHostReservationOfferingsAPIClient is a client that implements the
// DescribeHostReservationOfferings operation.
type DescribeHostReservationOfferingsAPIClient interface {
	DescribeHostReservationOfferings(context.Context, *DescribeHostReservationOfferingsInput, ...func(*Options)) (*DescribeHostReservationOfferingsOutput, error)
}

var _ DescribeHostReservationOfferingsAPIClient = (*Client)(nil)

// DescribeHostReservationOfferingsPaginatorOptions is the paginator options for
// DescribeHostReservationOfferings
type DescribeHostReservationOfferingsPaginatorOptions struct {
	// The maximum number of results to return for the request in a single page. The
	// remaining results can be seen by sending another request with the returned
	// nextToken value. This value can be between 5 and 500. If maxResults is given a
	// larger value than 500, you receive an error.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeHostReservationOfferingsPaginator is a paginator for
// DescribeHostReservationOfferings
type DescribeHostReservationOfferingsPaginator struct {
	options   DescribeHostReservationOfferingsPaginatorOptions
	client    DescribeHostReservationOfferingsAPIClient
	params    *DescribeHostReservationOfferingsInput
	nextToken *string
	firstPage bool
}

// NewDescribeHostReservationOfferingsPaginator returns a new
// DescribeHostReservationOfferingsPaginator
func NewDescribeHostReservationOfferingsPaginator(client DescribeHostReservationOfferingsAPIClient, params *DescribeHostReservationOfferingsInput, optFns ...func(*DescribeHostReservationOfferingsPaginatorOptions)) *DescribeHostReservationOfferingsPaginator {
	if params == nil {
		params = &DescribeHostReservationOfferingsInput{}
	}

	options := DescribeHostReservationOfferingsPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeHostReservationOfferingsPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeHostReservationOfferingsPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next DescribeHostReservationOfferings page.
func (p *DescribeHostReservationOfferingsPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeHostReservationOfferingsOutput, error) {
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

	result, err := p.client.DescribeHostReservationOfferings(ctx, &params, optFns...)
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

func newServiceMetadataMiddleware_opDescribeHostReservationOfferings(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeHostReservationOfferings",
	}
}
