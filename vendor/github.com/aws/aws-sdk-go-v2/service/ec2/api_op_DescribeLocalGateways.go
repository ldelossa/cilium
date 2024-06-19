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

// Describes one or more local gateways. By default, all local gateways are
// described. Alternatively, you can filter the results.
func (c *Client) DescribeLocalGateways(ctx context.Context, params *DescribeLocalGatewaysInput, optFns ...func(*Options)) (*DescribeLocalGatewaysOutput, error) {
	if params == nil {
		params = &DescribeLocalGatewaysInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeLocalGateways", params, optFns, c.addOperationDescribeLocalGatewaysMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeLocalGatewaysOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeLocalGatewaysInput struct {

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// One or more filters.
	//
	//   - local-gateway-id - The ID of a local gateway.
	//
	//   - outpost-arn - The Amazon Resource Name (ARN) of the Outpost.
	//
	//   - owner-id - The ID of the Amazon Web Services account that owns the local
	//   gateway.
	//
	//   - state - The state of the association.
	Filters []types.Filter

	// The IDs of the local gateways.
	LocalGatewayIds []string

	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	MaxResults *int32

	// The token for the next page of results.
	NextToken *string

	noSmithyDocumentSerde
}

type DescribeLocalGatewaysOutput struct {

	// Information about the local gateways.
	LocalGateways []types.LocalGateway

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeLocalGatewaysMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeLocalGateways{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeLocalGateways{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeLocalGateways"); err != nil {
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeLocalGateways(options.Region), middleware.Before); err != nil {
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

// DescribeLocalGatewaysAPIClient is a client that implements the
// DescribeLocalGateways operation.
type DescribeLocalGatewaysAPIClient interface {
	DescribeLocalGateways(context.Context, *DescribeLocalGatewaysInput, ...func(*Options)) (*DescribeLocalGatewaysOutput, error)
}

var _ DescribeLocalGatewaysAPIClient = (*Client)(nil)

// DescribeLocalGatewaysPaginatorOptions is the paginator options for
// DescribeLocalGateways
type DescribeLocalGatewaysPaginatorOptions struct {
	// The maximum number of results to return with a single call. To retrieve the
	// remaining results, make another call with the returned nextToken value.
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeLocalGatewaysPaginator is a paginator for DescribeLocalGateways
type DescribeLocalGatewaysPaginator struct {
	options   DescribeLocalGatewaysPaginatorOptions
	client    DescribeLocalGatewaysAPIClient
	params    *DescribeLocalGatewaysInput
	nextToken *string
	firstPage bool
}

// NewDescribeLocalGatewaysPaginator returns a new DescribeLocalGatewaysPaginator
func NewDescribeLocalGatewaysPaginator(client DescribeLocalGatewaysAPIClient, params *DescribeLocalGatewaysInput, optFns ...func(*DescribeLocalGatewaysPaginatorOptions)) *DescribeLocalGatewaysPaginator {
	if params == nil {
		params = &DescribeLocalGatewaysInput{}
	}

	options := DescribeLocalGatewaysPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeLocalGatewaysPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeLocalGatewaysPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next DescribeLocalGateways page.
func (p *DescribeLocalGatewaysPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeLocalGatewaysOutput, error) {
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

	result, err := p.client.DescribeLocalGateways(ctx, &params, optFns...)
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

func newServiceMetadataMiddleware_opDescribeLocalGateways(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeLocalGateways",
	}
}
