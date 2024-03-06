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

// Modifies the placement attributes for a specified instance. You can do the
// following:
//   - Modify the affinity between an instance and a Dedicated Host (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/dedicated-hosts-overview.html)
//     . When affinity is set to host and the instance is not associated with a
//     specific Dedicated Host, the next time the instance is started, it is
//     automatically associated with the host on which it lands. If the instance is
//     restarted or rebooted, this relationship persists.
//   - Change the Dedicated Host with which an instance is associated.
//   - Change the instance tenancy of an instance.
//   - Move an instance to or from a placement group (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html)
//     .
//
// At least one attribute for affinity, host ID, tenancy, or placement group name
// must be specified in the request. Affinity and tenancy can be modified in the
// same request. To modify the host ID, tenancy, placement group, or partition for
// an instance, the instance must be in the stopped state.
func (c *Client) ModifyInstancePlacement(ctx context.Context, params *ModifyInstancePlacementInput, optFns ...func(*Options)) (*ModifyInstancePlacementOutput, error) {
	if params == nil {
		params = &ModifyInstancePlacementInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "ModifyInstancePlacement", params, optFns, c.addOperationModifyInstancePlacementMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*ModifyInstancePlacementOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type ModifyInstancePlacementInput struct {

	// The ID of the instance that you are modifying.
	//
	// This member is required.
	InstanceId *string

	// The affinity setting for the instance. For more information, see Host affinity (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-dedicated-hosts-work.html#dedicated-hosts-affinity)
	// in the Amazon EC2 User Guide.
	Affinity types.Affinity

	// The Group Id of a placement group. You must specify the Placement Group Group
	// Id to launch an instance in a shared placement group.
	GroupId *string

	// The name of the placement group in which to place the instance. For spread
	// placement groups, the instance must have a tenancy of default . For cluster and
	// partition placement groups, the instance must have a tenancy of default or
	// dedicated . To remove an instance from a placement group, specify an empty
	// string ("").
	GroupName *string

	// The ID of the Dedicated Host with which to associate the instance.
	HostId *string

	// The ARN of the host resource group in which to place the instance. The instance
	// must have a tenancy of host to specify this parameter.
	HostResourceGroupArn *string

	// The number of the partition in which to place the instance. Valid only if the
	// placement group strategy is set to partition .
	PartitionNumber *int32

	// The tenancy for the instance. For T3 instances, you must launch the instance on
	// a Dedicated Host to use a tenancy of host . You can't change the tenancy from
	// host to dedicated or default . Attempting to make one of these unsupported
	// tenancy changes results in an InvalidRequest error code.
	Tenancy types.HostTenancy

	noSmithyDocumentSerde
}

type ModifyInstancePlacementOutput struct {

	// Is true if the request succeeds, and an error otherwise.
	Return *bool

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationModifyInstancePlacementMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpModifyInstancePlacement{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpModifyInstancePlacement{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "ModifyInstancePlacement"); err != nil {
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
	if err = addOpModifyInstancePlacementValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opModifyInstancePlacement(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opModifyInstancePlacement(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "ModifyInstancePlacement",
	}
}
