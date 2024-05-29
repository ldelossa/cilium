/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#undef host_egress_policy_hook
static __always_inline int
host_egress_policy_hook(struct __ctx_buff *ctx __maybe_unused,
			__u32 src_sec_identity __maybe_unused,
			__s8 *ext_err __maybe_unused)
{
       return CTX_ACT_OK;
}
