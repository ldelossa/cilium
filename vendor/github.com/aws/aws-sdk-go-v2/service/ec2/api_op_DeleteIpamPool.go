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

// Delete an IPAM pool.
//
// You cannot delete an IPAM pool if there are allocations in it or CIDRs
// provisioned to it. To release allocations, see [ReleaseIpamPoolAllocation]. To deprovision pool CIDRs, see [DeprovisionIpamPoolCidr]
// .
//
// For more information, see [Delete a pool] in the Amazon VPC IPAM User Guide.
//
// [ReleaseIpamPoolAllocation]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReleaseIpamPoolAllocation.html
// [Delete a pool]: https://docs.aws.amazon.com/vpc/latest/ipam/delete-pool-ipam.html
// [DeprovisionIpamPoolCidr]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeprovisionIpamPoolCidr.html
func (c *Client) DeleteIpamPool(ctx context.Context, params *DeleteIpamPoolInput, optFns ...func(*Options)) (*DeleteIpamPoolOutput, error) {
	if params == nil {
		params = &DeleteIpamPoolInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DeleteIpamPool", params, optFns, c.addOperationDeleteIpamPoolMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DeleteIpamPoolOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DeleteIpamPoolInput struct {

	// The ID of the pool to delete.
	//
	// This member is required.
	IpamPoolId *string

	// Enables you to quickly delete an IPAM pool and all resources within that pool,
	// including provisioned CIDRs, allocations, and other pools.
	//
	// You can only use this option to delete pools in the private scope or pools in
	// the public scope with a source resource. A source resource is a resource used to
	// provision CIDRs to a resource planning pool.
	Cascade *bool

	// A check for whether you have the required permissions for the action without
	// actually making the request and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	noSmithyDocumentSerde
}

type DeleteIpamPoolOutput struct {

	// Information about the results of the deletion.
	IpamPool *types.IpamPool

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDeleteIpamPoolMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDeleteIpamPool{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDeleteIpamPool{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DeleteIpamPool"); err != nil {
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
	if err = addUserAgentRetryMode(stack, options); err != nil {
		return err
	}
	if err = addOpDeleteIpamPoolValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDeleteIpamPool(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opDeleteIpamPool(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DeleteIpamPool",
	}
}
