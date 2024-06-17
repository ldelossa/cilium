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

// Describes a tree-based hierarchy that represents the physical host placement of
// your EC2 instances within an Availability Zone or Local Zone. You can use this
// information to determine the relative proximity of your EC2 instances within the
// Amazon Web Services network to support your tightly coupled workloads.
//
// Limitations
//
//   - Supported zones
//
//   - Availability Zone
//
//   - Local Zone
//
//   - Supported instance types
//
//   - hpc6a.48xlarge | hpc6id.32xlarge | hpc7a.12xlarge | hpc7a.24xlarge |
//     hpc7a.48xlarge | hpc7a.96xlarge | hpc7g.4xlarge | hpc7g.8xlarge |
//     hpc7g.16xlarge
//
//   - p3dn.24xlarge | p4d.24xlarge | p4de.24xlarge | p5.48xlarge
//
//   - trn1.2xlarge | trn1.32xlarge | trn1n.32xlarge
//
// For more information, see [Amazon EC2 instance topology] in the Amazon EC2 User Guide.
//
// [Amazon EC2 instance topology]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-topology.html
func (c *Client) DescribeInstanceTopology(ctx context.Context, params *DescribeInstanceTopologyInput, optFns ...func(*Options)) (*DescribeInstanceTopologyOutput, error) {
	if params == nil {
		params = &DescribeInstanceTopologyInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeInstanceTopology", params, optFns, c.addOperationDescribeInstanceTopologyMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeInstanceTopologyOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeInstanceTopologyInput struct {

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// The filters.
	//
	//   - availability-zone - The name of the Availability Zone (for example,
	//   us-west-2a ) or Local Zone (for example, us-west-2-lax-1b ) that the instance
	//   is in.
	//
	//   - instance-type - The instance type (for example, p4d.24xlarge ) or instance
	//   family (for example, p4d* ). You can use the * wildcard to match zero or more
	//   characters, or the ? wildcard to match zero or one character.
	//
	//   - zone-id - The ID of the Availability Zone (for example, usw2-az2 ) or Local
	//   Zone (for example, usw2-lax1-az1 ) that the instance is in.
	Filters []types.Filter

	// The name of the placement group that each instance is in.
	//
	// Constraints: Maximum 100 explicitly specified placement group names.
	GroupNames []string

	// The instance IDs.
	//
	// Default: Describes all your instances.
	//
	// Constraints: Maximum 100 explicitly specified instance IDs.
	InstanceIds []string

	// The maximum number of items to return for this request. To get the next page of
	// items, make another request with the token returned in the output. For more
	// information, see [Pagination].
	//
	// You can't specify this parameter and the instance IDs parameter in the same
	// request.
	//
	// Default: 20
	//
	// [Pagination]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination
	MaxResults *int32

	// The token returned from a previous paginated request. Pagination continues from
	// the end of the items returned by the previous request.
	NextToken *string

	noSmithyDocumentSerde
}

type DescribeInstanceTopologyOutput struct {

	// Information about the topology of each instance.
	Instances []types.InstanceTopology

	// The token to include in another request to get the next page of items. This
	// value is null when there are no more items to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeInstanceTopologyMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeInstanceTopology{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeInstanceTopology{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeInstanceTopology"); err != nil {
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeInstanceTopology(options.Region), middleware.Before); err != nil {
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

// DescribeInstanceTopologyAPIClient is a client that implements the
// DescribeInstanceTopology operation.
type DescribeInstanceTopologyAPIClient interface {
	DescribeInstanceTopology(context.Context, *DescribeInstanceTopologyInput, ...func(*Options)) (*DescribeInstanceTopologyOutput, error)
}

var _ DescribeInstanceTopologyAPIClient = (*Client)(nil)

// DescribeInstanceTopologyPaginatorOptions is the paginator options for
// DescribeInstanceTopology
type DescribeInstanceTopologyPaginatorOptions struct {
	// The maximum number of items to return for this request. To get the next page of
	// items, make another request with the token returned in the output. For more
	// information, see [Pagination].
	//
	// You can't specify this parameter and the instance IDs parameter in the same
	// request.
	//
	// Default: 20
	//
	// [Pagination]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html#api-pagination
	Limit int32

	// Set to true if pagination should stop if the service returns a pagination token
	// that matches the most recent token provided to the service.
	StopOnDuplicateToken bool
}

// DescribeInstanceTopologyPaginator is a paginator for DescribeInstanceTopology
type DescribeInstanceTopologyPaginator struct {
	options   DescribeInstanceTopologyPaginatorOptions
	client    DescribeInstanceTopologyAPIClient
	params    *DescribeInstanceTopologyInput
	nextToken *string
	firstPage bool
}

// NewDescribeInstanceTopologyPaginator returns a new
// DescribeInstanceTopologyPaginator
func NewDescribeInstanceTopologyPaginator(client DescribeInstanceTopologyAPIClient, params *DescribeInstanceTopologyInput, optFns ...func(*DescribeInstanceTopologyPaginatorOptions)) *DescribeInstanceTopologyPaginator {
	if params == nil {
		params = &DescribeInstanceTopologyInput{}
	}

	options := DescribeInstanceTopologyPaginatorOptions{}
	if params.MaxResults != nil {
		options.Limit = *params.MaxResults
	}

	for _, fn := range optFns {
		fn(&options)
	}

	return &DescribeInstanceTopologyPaginator{
		options:   options,
		client:    client,
		params:    params,
		firstPage: true,
		nextToken: params.NextToken,
	}
}

// HasMorePages returns a boolean indicating whether more pages are available
func (p *DescribeInstanceTopologyPaginator) HasMorePages() bool {
	return p.firstPage || (p.nextToken != nil && len(*p.nextToken) != 0)
}

// NextPage retrieves the next DescribeInstanceTopology page.
func (p *DescribeInstanceTopologyPaginator) NextPage(ctx context.Context, optFns ...func(*Options)) (*DescribeInstanceTopologyOutput, error) {
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

	result, err := p.client.DescribeInstanceTopology(ctx, &params, optFns...)
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

func newServiceMetadataMiddleware_opDescribeInstanceTopology(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeInstanceTopology",
	}
}
