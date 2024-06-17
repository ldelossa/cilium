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

// Launches the specified Scheduled Instances.
//
// Before you can launch a Scheduled Instance, you must purchase it and obtain an
// identifier using PurchaseScheduledInstances.
//
// You must launch a Scheduled Instance during its scheduled time period. You
// can't stop or reboot a Scheduled Instance, but you can terminate it as needed.
// If you terminate a Scheduled Instance before the current scheduled time period
// ends, you can launch it again after a few minutes.
func (c *Client) RunScheduledInstances(ctx context.Context, params *RunScheduledInstancesInput, optFns ...func(*Options)) (*RunScheduledInstancesOutput, error) {
	if params == nil {
		params = &RunScheduledInstancesInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "RunScheduledInstances", params, optFns, c.addOperationRunScheduledInstancesMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*RunScheduledInstancesOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Contains the parameters for RunScheduledInstances.
type RunScheduledInstancesInput struct {

	// The launch specification. You must match the instance type, Availability Zone,
	// network, and platform of the schedule that you purchased.
	//
	// This member is required.
	LaunchSpecification *types.ScheduledInstancesLaunchSpecification

	// The Scheduled Instance ID.
	//
	// This member is required.
	ScheduledInstanceId *string

	// Unique, case-sensitive identifier that ensures the idempotency of the request.
	// For more information, see [Ensuring Idempotency].
	//
	// [Ensuring Idempotency]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html
	ClientToken *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// The number of instances.
	//
	// Default: 1
	InstanceCount *int32

	noSmithyDocumentSerde
}

// Contains the output of RunScheduledInstances.
type RunScheduledInstancesOutput struct {

	// The IDs of the newly launched instances.
	InstanceIdSet []string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationRunScheduledInstancesMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpRunScheduledInstances{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpRunScheduledInstances{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "RunScheduledInstances"); err != nil {
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
	if err = addIdempotencyToken_opRunScheduledInstancesMiddleware(stack, options); err != nil {
		return err
	}
	if err = addOpRunScheduledInstancesValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opRunScheduledInstances(options.Region), middleware.Before); err != nil {
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

type idempotencyToken_initializeOpRunScheduledInstances struct {
	tokenProvider IdempotencyTokenProvider
}

func (*idempotencyToken_initializeOpRunScheduledInstances) ID() string {
	return "OperationIdempotencyTokenAutoFill"
}

func (m *idempotencyToken_initializeOpRunScheduledInstances) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	if m.tokenProvider == nil {
		return next.HandleInitialize(ctx, in)
	}

	input, ok := in.Parameters.(*RunScheduledInstancesInput)
	if !ok {
		return out, metadata, fmt.Errorf("expected middleware input to be of type *RunScheduledInstancesInput ")
	}

	if input.ClientToken == nil {
		t, err := m.tokenProvider.GetIdempotencyToken()
		if err != nil {
			return out, metadata, err
		}
		input.ClientToken = &t
	}
	return next.HandleInitialize(ctx, in)
}
func addIdempotencyToken_opRunScheduledInstancesMiddleware(stack *middleware.Stack, cfg Options) error {
	return stack.Initialize.Add(&idempotencyToken_initializeOpRunScheduledInstances{tokenProvider: cfg.IdempotencyTokenProvider}, middleware.Before)
}

func newServiceMetadataMiddleware_opRunScheduledInstances(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "RunScheduledInstances",
	}
}
