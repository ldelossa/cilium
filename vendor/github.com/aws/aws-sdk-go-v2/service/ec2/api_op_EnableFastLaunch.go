// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"time"
)

// When you enable Windows fast launch for a Windows AMI, images are
// pre-provisioned, using snapshots to launch instances up to 65% faster. To create
// the optimized Windows image, Amazon EC2 launches an instance and runs through
// Sysprep steps, rebooting as required. Then it creates a set of reserved
// snapshots that are used for subsequent launches. The reserved snapshots are
// automatically replenished as they are used, depending on your settings for
// launch frequency.
//
// You can only change these settings for Windows AMIs that you own or that have
// been shared with you.
func (c *Client) EnableFastLaunch(ctx context.Context, params *EnableFastLaunchInput, optFns ...func(*Options)) (*EnableFastLaunchOutput, error) {
	if params == nil {
		params = &EnableFastLaunchInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "EnableFastLaunch", params, optFns, c.addOperationEnableFastLaunchMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*EnableFastLaunchOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type EnableFastLaunchInput struct {

	// Specify the ID of the image for which to enable Windows fast launch.
	//
	// This member is required.
	ImageId *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// The launch template to use when launching Windows instances from
	// pre-provisioned snapshots. Launch template parameters can include either the
	// name or ID of the launch template, but not both.
	LaunchTemplate *types.FastLaunchLaunchTemplateSpecificationRequest

	// The maximum number of instances that Amazon EC2 can launch at the same time to
	// create pre-provisioned snapshots for Windows fast launch. Value must be 6 or
	// greater.
	MaxParallelLaunches *int32

	// The type of resource to use for pre-provisioning the AMI for Windows fast
	// launch. Supported values include: snapshot , which is the default value.
	ResourceType *string

	// Configuration settings for creating and managing the snapshots that are used
	// for pre-provisioning the AMI for Windows fast launch. The associated
	// ResourceType must be snapshot .
	SnapshotConfiguration *types.FastLaunchSnapshotConfigurationRequest

	noSmithyDocumentSerde
}

type EnableFastLaunchOutput struct {

	// The image ID that identifies the AMI for which Windows fast launch was enabled.
	ImageId *string

	// The launch template that is used when launching Windows instances from
	// pre-provisioned snapshots.
	LaunchTemplate *types.FastLaunchLaunchTemplateSpecificationResponse

	// The maximum number of instances that Amazon EC2 can launch at the same time to
	// create pre-provisioned snapshots for Windows fast launch.
	MaxParallelLaunches *int32

	// The owner ID for the AMI for which Windows fast launch was enabled.
	OwnerId *string

	// The type of resource that was defined for pre-provisioning the AMI for Windows
	// fast launch.
	ResourceType types.FastLaunchResourceType

	// Settings to create and manage the pre-provisioned snapshots that Amazon EC2
	// uses for faster launches from the Windows AMI. This property is returned when
	// the associated resourceType is snapshot .
	SnapshotConfiguration *types.FastLaunchSnapshotConfigurationResponse

	// The current state of Windows fast launch for the specified AMI.
	State types.FastLaunchStateCode

	// The reason that the state changed for Windows fast launch for the AMI.
	StateTransitionReason *string

	// The time that the state changed for Windows fast launch for the AMI.
	StateTransitionTime *time.Time

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationEnableFastLaunchMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpEnableFastLaunch{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpEnableFastLaunch{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "EnableFastLaunch"); err != nil {
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
	if err = addOpEnableFastLaunchValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opEnableFastLaunch(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opEnableFastLaunch(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "EnableFastLaunch",
	}
}
