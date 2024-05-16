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

// Locks an Amazon EBS snapshot in either governance or compliance mode to protect
// it against accidental or malicious deletions for a specific duration. A locked
// snapshot can't be deleted.
//
// You can also use this action to modify the lock settings for a snapshot that is
// already locked. The allowed modifications depend on the lock mode and lock
// state:
//
//   - If the snapshot is locked in governance mode, you can modify the lock mode
//     and the lock duration or lock expiration date.
//
//   - If the snapshot is locked in compliance mode and it is in the cooling-off
//     period, you can modify the lock mode and the lock duration or lock expiration
//     date.
//
//   - If the snapshot is locked in compliance mode and the cooling-off period has
//     lapsed, you can only increase the lock duration or extend the lock expiration
//     date.
func (c *Client) LockSnapshot(ctx context.Context, params *LockSnapshotInput, optFns ...func(*Options)) (*LockSnapshotOutput, error) {
	if params == nil {
		params = &LockSnapshotInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "LockSnapshot", params, optFns, c.addOperationLockSnapshotMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*LockSnapshotOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type LockSnapshotInput struct {

	// The mode in which to lock the snapshot. Specify one of the following:
	//
	//   - governance - Locks the snapshot in governance mode. Snapshots locked in
	//   governance mode can't be deleted until one of the following conditions are met:
	//
	//   - The lock duration expires.
	//
	//   - The snapshot is unlocked by a user with the appropriate permissions.
	//
	// Users with the appropriate IAM permissions can unlock the snapshot, increase or
	//   decrease the lock duration, and change the lock mode to compliance at any time.
	//
	// If you lock a snapshot in governance mode, omit CoolOffPeriod.
	//
	//   - compliance - Locks the snapshot in compliance mode. Snapshots locked in
	//   compliance mode can't be unlocked by any user. They can be deleted only after
	//   the lock duration expires. Users can't decrease the lock duration or change the
	//   lock mode to governance . However, users with appropriate IAM permissions can
	//   increase the lock duration at any time.
	//
	// If you lock a snapshot in compliance mode, you can optionally specify
	//   CoolOffPeriod.
	//
	// This member is required.
	LockMode types.LockMode

	// The ID of the snapshot to lock.
	//
	// This member is required.
	SnapshotId *string

	// The cooling-off period during which you can unlock the snapshot or modify the
	// lock settings after locking the snapshot in compliance mode, in hours. After the
	// cooling-off period expires, you can't unlock or delete the snapshot, decrease
	// the lock duration, or change the lock mode. You can increase the lock duration
	// after the cooling-off period expires.
	//
	// The cooling-off period is optional when locking a snapshot in compliance mode.
	// If you are locking the snapshot in governance mode, omit this parameter.
	//
	// To lock the snapshot in compliance mode immediately without a cooling-off
	// period, omit this parameter.
	//
	// If you are extending the lock duration for a snapshot that is locked in
	// compliance mode after the cooling-off period has expired, omit this parameter.
	// If you specify a cooling-period in a such a request, the request fails.
	//
	// Allowed values: Min 1, max 72.
	CoolOffPeriod *int32

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// The date and time at which the snapshot lock is to automatically expire, in the
	// UTC time zone ( YYYY-MM-DDThh:mm:ss.sssZ ).
	//
	// You must specify either this parameter or LockDuration, but not both.
	ExpirationDate *time.Time

	// The period of time for which to lock the snapshot, in days. The snapshot lock
	// will automatically expire after this period lapses.
	//
	// You must specify either this parameter or ExpirationDate, but not both.
	//
	// Allowed values: Min: 1, max 36500
	LockDuration *int32

	noSmithyDocumentSerde
}

type LockSnapshotOutput struct {

	// The compliance mode cooling-off period, in hours.
	CoolOffPeriod *int32

	// The date and time at which the compliance mode cooling-off period expires, in
	// the UTC time zone ( YYYY-MM-DDThh:mm:ss.sssZ ).
	CoolOffPeriodExpiresOn *time.Time

	// The date and time at which the snapshot was locked, in the UTC time zone (
	// YYYY-MM-DDThh:mm:ss.sssZ ).
	LockCreatedOn *time.Time

	// The period of time for which the snapshot is locked, in days.
	LockDuration *int32

	// The date and time at which the lock duration started, in the UTC time zone (
	// YYYY-MM-DDThh:mm:ss.sssZ ).
	LockDurationStartTime *time.Time

	// The date and time at which the lock will expire, in the UTC time zone (
	// YYYY-MM-DDThh:mm:ss.sssZ ).
	LockExpiresOn *time.Time

	// The state of the snapshot lock. Valid states include:
	//
	//   - compliance-cooloff - The snapshot has been locked in compliance mode but it
	//   is still within the cooling-off period. The snapshot can't be deleted, but it
	//   can be unlocked and the lock settings can be modified by users with appropriate
	//   permissions.
	//
	//   - governance - The snapshot is locked in governance mode. The snapshot can't
	//   be deleted, but it can be unlocked and the lock settings can be modified by
	//   users with appropriate permissions.
	//
	//   - compliance - The snapshot is locked in compliance mode and the cooling-off
	//   period has expired. The snapshot can't be unlocked or deleted. The lock duration
	//   can only be increased by users with appropriate permissions.
	//
	//   - expired - The snapshot was locked in compliance or governance mode but the
	//   lock duration has expired. The snapshot is not locked and can be deleted.
	LockState types.LockState

	// The ID of the snapshot
	SnapshotId *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationLockSnapshotMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpLockSnapshot{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpLockSnapshot{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "LockSnapshot"); err != nil {
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
	if err = addOpLockSnapshotValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opLockSnapshot(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opLockSnapshot(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "LockSnapshot",
	}
}
