// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/trace.h>

#define IF_TRUE_SET_ERRNO_JUMP(cond, errno, dest)  \
    if (cond)                                      \
    {                                              \
        oe_errno = errno;                          \
        OE_TRACE_ERROR("oe_errno =%d ", oe_errno); \
        goto dest;                                 \
    }
