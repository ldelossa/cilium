/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ENTERPRISE_NAT_H_
#define __LIB_ENTERPRISE_NAT_H_

#include "enterprise_cilium_mesh.h"

#undef snat_v4_needs_masquerade_hook
static __always_inline int
snat_v4_needs_masquerade_hook(struct __ctx_buff *ctx __maybe_unused,
			      struct ipv4_nat_target *target __maybe_unused)
{
#if defined(CILIUM_MESH)
      return cilium_mesh_snat_v4_needs_masquerade(ctx, target);
#endif

      return 0;
}

#endif /* __LIB_ENTERPRISE_NAT_H_ */