// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _PAL_ATOMIC_UINT32_H_
#define _PAL_ATOMIC_UINT32_H_

#if _MSC_VER
#include <Windows.h>
#endif

#ifdef _MSC_VER
typedef LONG volatile* atomic_uint32_ptr_t;
#elif defined __GNUC__
typedef uint32_t* atomic_uint32_ptr_t;
#endif

static __inline uint32_t atomic_uint32_load(atomic_uint32_ptr_t p_val)
{
#ifdef _MSC_VER
    return InterlockedCompareExchange(p_val, 0, 0);
#elif defined __GNUC__
    return __sync_val_compare_and_swap(p_val, 0, 0);
#endif
}

static __inline void atomic_uint32_store(
    atomic_uint32_ptr_t p_val,
    uint32_t val)
{
#ifdef _MSC_VER
    InterlockedExchange(p_val, val);
#elif defined __GNUC__
    uint32_t expect = 0;
    uint32_t actual = 0;
    while ((actual = __sync_val_compare_and_swap(p_val, expect, val)) != expect)
    {
        expect = actual;
    }
#endif
}

static __inline uint32_t atomic_uint32_compare_exchange(
    atomic_uint32_ptr_t p_val,
    uint32_t expected,
    uint32_t val)
{
#ifdef _MSC_VER
    return InterlockedCompareExchange(p_val, val, expected);
#elif defined __GNUC__
    return __sync_val_compare_and_swap(p_val, expected, val);
#endif
}

#endif // _PAL_ATOMIC_UINT32_H_
