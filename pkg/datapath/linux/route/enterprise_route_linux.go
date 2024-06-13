//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build linux

package route

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

// DeleteV4 deletes an IPv4 Linux route. Differently from Delete, it does
// not discard Priority, Local, Type, MTU and Scope fields.
// An error is returned if the route does not exist or if the route could not be deleted.
func DeleteV4(route Route) error {
	link, err := netlink.LinkByName(route.Device)
	if err != nil {
		return fmt.Errorf("unable to lookup interface %s: %w", route.Device, err)
	}

	routeSpec := route.getNetlinkRoute()
	routeSpec.LinkIndex = link.Attrs().Index

	if err := netlink.RouteDel(&routeSpec); err != nil {
		return err
	}

	return nil
}
