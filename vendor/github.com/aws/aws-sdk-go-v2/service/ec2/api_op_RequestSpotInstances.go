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

// Creates a Spot Instance request.
//
// For more information, see [Work with Spot Instance] in the Amazon EC2 User Guide.
//
// We strongly discourage using the RequestSpotInstances API because it is a
// legacy API with no planned investment. For options for requesting Spot
// Instances, see [Which is the best Spot request method to use?]in the Amazon EC2 User Guide.
//
// [Work with Spot Instance]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-requests.html
// [Which is the best Spot request method to use?]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-best-practices.html#which-spot-request-method-to-use
func (c *Client) RequestSpotInstances(ctx context.Context, params *RequestSpotInstancesInput, optFns ...func(*Options)) (*RequestSpotInstancesOutput, error) {
	if params == nil {
		params = &RequestSpotInstancesInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "RequestSpotInstances", params, optFns, c.addOperationRequestSpotInstancesMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*RequestSpotInstancesOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Contains the parameters for RequestSpotInstances.
type RequestSpotInstancesInput struct {

	// The user-specified name for a logical grouping of requests.
	//
	// When you specify an Availability Zone group in a Spot Instance request, all
	// Spot Instances in the request are launched in the same Availability Zone.
	// Instance proximity is maintained with this parameter, but the choice of
	// Availability Zone is not. The group applies only to requests for Spot Instances
	// of the same instance type. Any additional Spot Instance requests that are
	// specified with the same Availability Zone group name are launched in that same
	// Availability Zone, as long as at least one instance from the group is still
	// active.
	//
	// If there is no active instance running in the Availability Zone group that you
	// specify for a new Spot Instance request (all instances are terminated, the
	// request is expired, or the maximum price you specified falls below current Spot
	// price), then Amazon EC2 launches the instance in any Availability Zone where the
	// constraint can be met. Consequently, the subsequent set of Spot Instances could
	// be placed in a different zone from the original request, even if you specified
	// the same Availability Zone group.
	//
	// Default: Instances are launched in any available Availability Zone.
	AvailabilityZoneGroup *string

	// Deprecated.
	BlockDurationMinutes *int32

	// Unique, case-sensitive identifier that you provide to ensure the idempotency of
	// the request. For more information, see [Ensuring idempotency in Amazon EC2 API requests]in the Amazon EC2 User Guide.
	//
	// [Ensuring idempotency in Amazon EC2 API requests]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Run_Instance_Idempotency.html
	ClientToken *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// The maximum number of Spot Instances to launch.
	//
	// Default: 1
	InstanceCount *int32

	// The behavior when a Spot Instance is interrupted. The default is terminate .
	InstanceInterruptionBehavior types.InstanceInterruptionBehavior

	// The instance launch group. Launch groups are Spot Instances that launch
	// together and terminate together.
	//
	// Default: Instances are launched and terminated individually
	LaunchGroup *string

	// The launch specification.
	LaunchSpecification *types.RequestSpotLaunchSpecification

	// The maximum price per unit hour that you are willing to pay for a Spot
	// Instance. We do not recommend using this parameter because it can lead to
	// increased interruptions. If you do not specify this parameter, you will pay the
	// current Spot price.
	//
	// If you specify a maximum price, your instances will be interrupted more
	// frequently than if you do not specify this parameter.
	SpotPrice *string

	// The key-value pair for tagging the Spot Instance request on creation. The value
	// for ResourceType must be spot-instances-request , otherwise the Spot Instance
	// request fails. To tag the Spot Instance request after it has been created, see [CreateTags]
	// .
	//
	// [CreateTags]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateTags.html
	TagSpecifications []types.TagSpecification

	// The Spot Instance request type.
	//
	// Default: one-time
	Type types.SpotInstanceType

	// The start date of the request. If this is a one-time request, the request
	// becomes active at this date and time and remains active until all instances
	// launch, the request expires, or the request is canceled. If the request is
	// persistent, the request becomes active at this date and time and remains active
	// until it expires or is canceled.
	//
	// The specified start date and time cannot be equal to the current date and time.
	// You must specify a start date and time that occurs after the current date and
	// time.
	ValidFrom *time.Time

	// The end date of the request, in UTC format (YYYY-MM-DDTHH:MM:SSZ).
	//
	//   - For a persistent request, the request remains active until the ValidUntil
	//   date and time is reached. Otherwise, the request remains active until you cancel
	//   it.
	//
	//   - For a one-time request, the request remains active until all instances
	//   launch, the request is canceled, or the ValidUntil date and time is reached.
	//   By default, the request is valid for 7 days from the date the request was
	//   created.
	ValidUntil *time.Time

	noSmithyDocumentSerde
}

// Contains the output of RequestSpotInstances.
type RequestSpotInstancesOutput struct {

	// The Spot Instance requests.
	SpotInstanceRequests []types.SpotInstanceRequest

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationRequestSpotInstancesMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpRequestSpotInstances{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpRequestSpotInstances{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "RequestSpotInstances"); err != nil {
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
	if err = addOpRequestSpotInstancesValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opRequestSpotInstances(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opRequestSpotInstances(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "RequestSpotInstances",
	}
}
