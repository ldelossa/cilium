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

// Describes one or more local gateway route tables. By default, all local gateway
// route tables are described. Alternatively, you can filter the results.
func (c *Client) DescribeLocalGatewayRouteTables(ctx context.Context, params *DescribeLocalGatewayRouteTablesInput, optFns ...func(*Options)) (*DescribeLocalGatewayRouteTablesOutput, error) {
	if params == nil {
		params = &DescribeLocalGatewayRouteTablesInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeLocalGatewayRouteTables", params, optFns, c.addOperationDescribeLocalGatewayRouteTablesMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeLocalGatewayRouteTablesOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeLocalGatewayRouteTablesInput struct {

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// One or more filters.
	//
	//   - local-gateway-id - The ID of a local gateway.
	//
	//   - local-gateway-route-table-arn - The Amazon Resource Name (ARN) of the local
	//   gateway route table.
	//
	//   - local-gateway-route-table-id - The ID of a local gateway route table.
	//
	//   - outpost-arn - The Amazon Resource Name (ARN) of the Outpost.
	//
	//   - owner-id - The ID of the Amazon Web Services account that owns the local
	//   gateway route table.
	//
	//   - state - The state of the local gateway route table.
	Filters []types.Filter

	// The IDs of the local gateway route tables.
	LocalGatewayRouteTableIds []string

	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	MaxResults *int32

	// The token for the next page of results.
	NextToken *string

	noSmithyDocumentSerde
}

type DescribeLocalGatewayRouteTablesOutput struct {

	// Information about the local gateway route tables.
	LocalGatewayRouteTables []types.LocalGatewayRouteTable

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeLocalGatewayRouteTablesMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeLocalGatewayRouteTables{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeLocalGatewayRouteTables{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeLocalGatewayRouteTables"); err != nil {
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeLocalGatewayRouteTables(options.Region), middleware.Before); err != nil {
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

// DescribeLocalGatewayRouteTablesAPIClient is a client that implements the
// DescribeLocalGatewayRouteTables operation.
type DescribeLocalGatewayRouteTablesAPIClient interface {
	DescribeLocalGatewayRouteTables(context.Context, *DescribeLocalGatewayRouteTablesInput, ...func(*Options)) (*DescribeLocalGatewayRouteTablesOutput, error)
}

var _ DescribeLocalGatewayRouteTablesAPIClient = (*Client)(nil)

// DescribeLocalGatewayRouteTablesPaginatorOptions is the paginator options for
// DescribeLocalGatewayRouteTables
type DescribeLocalGatewayRouteTablesPaginatorOptions struct {
	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeLocalGatewayRouteTablesPaginator is a paginator for
// DescribeLocalGatewayRouteTables
type DescribeLocalGatewayRouteTablesPaginator struct {
	options   DescribeLocalGatewayRouteTablesPaginatorOptions
	client    DescribeLocalGatewayRouteTablesAPIClient
	params    *DescribeLocalGatewayRouteTablesInput
	nextToken *string
	firstPage bool
}

// NewDescribeLocalGatewayRouteTablesPaginator returns a new
// DescribeLocalGatewayRouteTablesPaginator
func NewDescribeLocalGatewayRouteTablesPaginator(client DescribeLocalGatewayRouteTablesAPIClient, params *DescribeLocalGatewayRouteTablesInput, optFns ...func(*DescribeLocalGatewayRouteTablesPaginatorOptions)) *DescribeLocalGatewayRouteTablesPaginator {
	if params == nil {
		params = &DescribeLocalGatewayRouteTablesInput{}
	}

	options := DescribeLocalGatewayRouteTablesPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeLocalGatewayRouteTablesPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeLocalGatewayRouteTablesPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next DescribeLocalGatewayRouteTables page.
func (p *DescribeLocalGatewayRouteTablesPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeLocalGatewayRouteTablesOutput, error) {
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

	result, err := p.client.DescribeLocalGatewayRouteTables(ctx, &params, optFns...)
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

func newServiceMetadataMiddleware_opDescribeLocalGatewayRouteTables(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeLocalGatewayRouteTables",
	}
}
