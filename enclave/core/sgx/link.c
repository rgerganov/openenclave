// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/sched.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/unistd.h>

/* oe_stderr is treated as an initializer and thus non-const by the compiler
 * so cannot just be statically added to symbols. Force inclusion by nesting
 * it in a wrapper function.
 */
void* _link_oe_stderr()
{
    return oe_stderr;
}

/* Calling this forces symbols to be available to subsequently linked libs. */
const void* oe_link_core(void)
{
    static const void* symbols[] = {
        _link_oe_stderr,
        oe_sbrk,
        oe_sched_yield,
    };

    return symbols;
}
