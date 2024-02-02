/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */
#ifndef ENTERPRISE_HEADER_NAMES_TO_IDS_H_
#define ENTERPRISE_HEADER_NAMES_TO_IDS_H_

/*
 * for documentation see __source_file_name_to_id in bpf/source_names_to_ids.h
 */
static __always_inline int
__enterprise_source_file_name_to_id(const char *const header_name __maybe_unused)
{
	/* @@ source files list begin */
	/* @@ source files list end */

	return 0;
}

#endif /* ENTERPRISE_HEADER_NAMES_TO_IDS_H_ */
