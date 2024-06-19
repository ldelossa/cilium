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

// Creates an entry (a rule) in a network ACL with the specified rule number. Each
// network ACL has a set of numbered ingress rules and a separate set of numbered
// egress rules. When determining whether a packet should be allowed in or out of a
// subnet associated with the ACL, we process the entries in the ACL according to
// the rule numbers, in ascending order. Each network ACL has a set of ingress
// rules and a separate set of egress rules.
//
// We recommend that you leave room between the rule numbers (for example, 100,
// 110, 120, ...), and not number them one right after the other (for example, 101,
// 102, 103, ...). This makes it easier to add a rule between existing ones without
// having to renumber the rules.
//
// After you add an entry, you can't modify it; you must either replace it, or
// create an entry and delete the old one.
//
// For more information about network ACLs, see [Network ACLs] in the Amazon VPC User Guide.
//
// [Network ACLs]: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
func (c *Client) CreateNetworkAclEntry(ctx context.Context, params *CreateNetworkAclEntryInput, optFns ...func(*Options)) (*CreateNetworkAclEntryOutput, error) {
	if params == nil {
		params = &CreateNetworkAclEntryInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CreateNetworkAclEntry", params, optFns, c.addOperationCreateNetworkAclEntryMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CreateNetworkAclEntryOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type CreateNetworkAclEntryInput struct {

	// Indicates whether this is an egress rule (rule is applied to traffic leaving
	// the subnet).
	//
	// This member is required.
	Egress *bool

	// The ID of the network ACL.
	//
	// This member is required.
	NetworkAclId *string

	// The protocol number. A value of "-1" means all protocols. If you specify "-1"
	// or a protocol number other than "6" (TCP), "17" (UDP), or "1" (ICMP), traffic on
	// all ports is allowed, regardless of any ports or ICMP types or codes that you
	// specify. If you specify protocol "58" (ICMPv6) and specify an IPv4 CIDR block,
	// traffic for all ICMP types and codes allowed, regardless of any that you
	// specify. If you specify protocol "58" (ICMPv6) and specify an IPv6 CIDR block,
	// you must specify an ICMP type and code.
	//
	// This member is required.
	Protocol *string

	// Indicates whether to allow or deny the traffic that matches the rule.
	//
	// This member is required.
	RuleAction types.RuleAction

	// The rule number for the entry (for example, 100). ACL entries are processed in
	// ascending order by rule number.
	//
	// Constraints: Positive integer from 1 to 32766. The range 32767 to 65535 is
	// reserved for internal use.
	//
	// This member is required.
	RuleNumber *int32

	// The IPv4 network range to allow or deny, in CIDR notation (for example
	// 172.16.0.0/24 ). We modify the specified CIDR block to its canonical form; for
	// example, if you specify 100.68.0.18/18 , we modify it to 100.68.0.0/18 .
	CidrBlock *string

	// Checks whether you have the required permissions for the action, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// ICMP protocol: The ICMP or ICMPv6 type and code. Required if specifying
	// protocol 1 (ICMP) or protocol 58 (ICMPv6) with an IPv6 CIDR block.
	IcmpTypeCode *types.IcmpTypeCode

	// The IPv6 network range to allow or deny, in CIDR notation (for example
	// 2001:db8:1234:1a00::/64 ).
	Ipv6CidrBlock *string

	// TCP or UDP protocols: The range of ports the rule applies to. Required if
	// specifying protocol 6 (TCP) or 17 (UDP).
	PortRange *types.PortRange

	noSmithyDocumentSerde
}

type CreateNetworkAclEntryOutput struct {
	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCreateNetworkAclEntryMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpCreateNetworkAclEntry{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpCreateNetworkAclEntry{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "CreateNetworkAclEntry"); err != nil {
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
	if err = addOpCreateNetworkAclEntryValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCreateNetworkAclEntry(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opCreateNetworkAclEntry(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "CreateNetworkAclEntry",
	}
}
