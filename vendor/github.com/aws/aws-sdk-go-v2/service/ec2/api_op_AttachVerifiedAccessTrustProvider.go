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

// Attaches the specified Amazon Web Services Verified Access trust provider to
// the specified Amazon Web Services Verified Access instance.
func (c *Client) AttachVerifiedAccessTrustProvider(ctx context.Context, params *AttachVerifiedAccessTrustProviderInput, optFns ...func(*Options)) (*AttachVerifiedAccessTrustProviderOutput, error) {
	if params == nil {
		params = &AttachVerifiedAccessTrustProviderInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "AttachVerifiedAccessTrustProvider", params, optFns, c.addOperationAttachVerifiedAccessTrustProviderMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*AttachVerifiedAccessTrustProviderOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type AttachVerifiedAccessTrustProviderInput struct {

	// The ID of the Verified Access instance.
	//
	// This member is required.
	VerifiedAccessInstanceId *string

	// The ID of the Verified Access trust provider.
	//
	// This member is required.
	VerifiedAccessTrustProviderId *string

	// A unique, case-sensitive token that you provide to ensure idempotency of your
	// modification request. For more information, see Ensuring Idempotency (https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html)
	// .
	ClientToken *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	noSmithyDocumentSerde
}

type AttachVerifiedAccessTrustProviderOutput struct {

	// Details about the Verified Access instance.
	VerifiedAccessInstance *types.VerifiedAccessInstance

	// Details about the Verified Access trust provider.
	VerifiedAccessTrustProvider *types.VerifiedAccessTrustProvider

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationAttachVerifiedAccessTrustProviderMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpAttachVerifiedAccessTrustProvider{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpAttachVerifiedAccessTrustProvider{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "AttachVerifiedAccessTrustProvider"); err != nil {
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
	if err = addIdempotencyToken_opAttachVerifiedAccessTrustProviderMiddleware(stack, options); err != nil {
		return err
	}
	if err = addOpAttachVerifiedAccessTrustProviderValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opAttachVerifiedAccessTrustProvider(options.Region), middleware.Before); err != nil {
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

type idempotencyToken_initializeOpAttachVerifiedAccessTrustProvider struct {
	tokenProvider IdempotencyTokenProvider
}

func (*idempotencyToken_initializeOpAttachVerifiedAccessTrustProvider) ID() string {
	return "OperationIdempotencyTokenAutoFill"
}

func (m *idempotencyToken_initializeOpAttachVerifiedAccessTrustProvider) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	if m.tokenProvider == nil {
		return next.HandleInitialize(ctx, in)
	}

	input, ok := in.Parameters.(*AttachVerifiedAccessTrustProviderInput)
	if !ok {
		return out, metadata, fmt.Errorf("expected middleware input to be of type *AttachVerifiedAccessTrustProviderInput ")
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
func addIdempotencyToken_opAttachVerifiedAccessTrustProviderMiddleware(stack *middleware.Stack, cfg Options) error {
	return stack.Initialize.Add(&idempotencyToken_initializeOpAttachVerifiedAccessTrustProvider{tokenProvider: cfg.IdempotencyTokenProvider}, middleware.Before)
}

func newServiceMetadataMiddleware_opAttachVerifiedAccessTrustProvider(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "AttachVerifiedAccessTrustProvider",
	}
}
