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

// This action is deprecated.
//
// Describes the ClassicLink status of the specified VPCs.
func (c *Client) DescribeVpcClassicLink(ctx context.Context, params *DescribeVpcClassicLinkInput, optFns ...func(*Options)) (*DescribeVpcClassicLinkOutput, error) {
	if params == nil {
		params = &DescribeVpcClassicLinkInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeVpcClassicLink", params, optFns, c.addOperationDescribeVpcClassicLinkMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeVpcClassicLinkOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeVpcClassicLinkInput struct {

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// The filters.
	//
	//   - is-classic-link-enabled - Whether the VPC is enabled for ClassicLink ( true
	//   | false ).
	//
	//   - tag : - The key/value combination of a tag assigned to the resource. Use the
	//   tag key in the filter name and the tag value as the filter value. For example,
	//   to find all resources that have a tag with the key Owner and the value TeamA ,
	//   specify tag:Owner for the filter name and TeamA for the filter value.
	//
	//   - tag-key - The key of a tag assigned to the resource. Use this filter to find
	//   all resources assigned a tag with a specific key, regardless of the tag value.
	Filters []types.Filter

	// The VPCs for which you want to describe the ClassicLink status.
	VpcIds []string

	noSmithyDocumentSerde
}

type DescribeVpcClassicLinkOutput struct {

	// The ClassicLink status of the VPCs.
	Vpcs []types.VpcClassicLink

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeVpcClassicLinkMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeVpcClassicLink{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeVpcClassicLink{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeVpcClassicLink"); err != nil {
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeVpcClassicLink(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opDescribeVpcClassicLink(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeVpcClassicLink",
	}
}
