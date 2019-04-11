// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _THREAD_CONTROL_H_
#define _THREAD_CONTROL_H_

#include <openenclave/bits/result.h>
#include <stdint.h>
#include <stdlib.h>
#include "lockless_queue.h"

#ifndef EXTERN
#ifdef __cplusplus
#define EXTERN extern "C"
#else
#define EXTERN
#endif
#endif

#ifdef _MSC_VER
typedef uint32_t volatile state_t;
typedef uint32_t volatile lock_t;
#elif defined __GNUC__
typedef uint32_t state_t;
typedef uint32_t lock_t;
#else
#error "unsupported"
#endif

enum ecall_type
{
    ET_SYNCHRONOUS,
    ET_ASYNCHRONOUS,
    ET_CALLBACK,
};

typedef struct _ecall_synchronous_data
{
    lock_t lock;
} ecall_synchronous_data;

typedef struct _ecall_asynchronous_data
{
} ecall_asynchronous_data;

typedef struct _ecall_callback_data
{
    void* callback;
} ecall_callback_data;

typedef struct _tc_queue_node
{
    lockless_queue_node _node;
    uint32_t type;
    union _data {
        ecall_synchronous_data sync;
        ecall_asynchronous_data async;
        ecall_callback_data callback;
    } data;
    uint32_t function_id;

    uint8_t* input_buffer;
    size_t input_buffer_size;
    uint8_t* output_buffer;
    size_t output_buffer_size;
    size_t output_bytes_written;
    oe_result_t result;

    // args has to be the final member
    // args is an implied member that doesn't really exist
    // uint8_t* args;
} tc_queue_node;

enum thread_control_state
{
    TC_RUNNING,
    TC_STOPPING,
    TC_STOPPED,
    TC_EXITED,
};

typedef struct _thread_control
{
    state_t _state;
    size_t count_limit;

    lockless_queue enc_queue;
    lockless_queue host_queue;
} thread_control;

EXTERN void init_thread_control(
    thread_control* ptc,
    uint32_t state,
    size_t count_limit);

EXTERN uint32_t tc_get_state(thread_control* ptc);

EXTERN void tc_set_state(thread_control* ptc, uint32_t state);

EXTERN void tc_push_enc_queue(thread_control* ptc, tc_queue_node* pnode);

EXTERN tc_queue_node* tc_pop_enc_queue(thread_control* ptc);

EXTERN void tc_push_host_queue(thread_control* ptc, tc_queue_node* pnode);

EXTERN tc_queue_node* tc_pop_host_queue(thread_control* ptc);

#endif // _THREAD_CONTROL_H_
