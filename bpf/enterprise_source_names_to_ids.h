/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/*
 * for documentation see __source_file_name_to_id in bpf/source_names_to_ids.h
 */
static __always_inline int
__enterprise_source_file_name_to_id(const char *const header_name)
{
	/* @@ source files list begin */

	/* enterprise source files from bpf/ */
	_strcase_(201, "enterprise_nodeport.h");

	/* @@ source files list end */

	return 0;
}
