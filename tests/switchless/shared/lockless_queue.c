// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "lockless_queue.h"

#include <stdlib.h>

#ifdef _MSC_VER
typedef void* volatile* value_ptr_t;
typedef void* value_t;
#elif defined __GNUC__
typedef atomic_lockless_node_ptr* value_ptr_t;
typedef lockless_queue_node* value_t;
#endif

static __inline value_t load(value_ptr_t obj)
{
#ifdef _MSC_VER
    return InterlockedCompareExchangePointer(obj, NULL, NULL);
#elif defined __GNUC__
    return __sync_val_compare_and_swap(obj, NULL, NULL);
#endif
}

static __inline void store(value_ptr_t obj, value_t val)
{
#ifdef _MSC_VER
    InterlockedExchangePointer(obj, val);
#elif defined __GNUC__
    value_t expect = NULL;
    value_t actual = NULL;
    while ((actual = __sync_val_compare_and_swap(obj, expect, val)) != expect)
    {
        expect = actual;
    }
#endif
}

static __inline value_t compare_exchange(
    value_ptr_t obj,
    value_t expected,
    value_t val)
{
#ifdef _MSC_VER
    return InterlockedCompareExchangePointer(obj, val, expected);
#elif defined __GNUC__
    return __sync_val_compare_and_swap(obj, expected, val);
#endif
}

/* functions for lockless_queue_node */
/*---------------------------------------------------------------------------*/
void init_lockless_queue_node(lockless_queue_node* p_node)
{
    store(&(p_node->p_link), NULL);
} /* init_lockless_queue_node */

/* functions for lockless_queue */
/*---------------------------------------------------------------------------*/
void init_lockless_queue(lockless_queue* p_queue)
{
    store(&(p_queue->p_in_link), NULL);
    store(&(p_queue->p_out_link), NULL);
} /* init_lockless_queue */

void lockless_queue_push(lockless_queue* p_queue, lockless_queue_node* p_node)
{
    lockless_queue_node* p_actual = load(&(p_queue->p_in_link));
    lockless_queue_node* p_expected = NULL;
    do
    {
        store(&(p_node->p_link), p_actual);
        p_expected = p_actual;
        p_actual = compare_exchange(&(p_queue->p_in_link), p_expected, p_node);
    } while (p_expected != p_actual);
} /* lockless_queue_push */

lockless_queue_node* lockless_queue_pop(lockless_queue* p_queue)
{
    // try to take a node from the output side
    lockless_queue_node* popped_node = load(&(p_queue->p_out_link));

    if (NULL != popped_node)
    {
        store(&(p_queue->p_out_link), load(&(popped_node->p_link)));
        store(&(popped_node->p_link), NULL);
    }
    else
    {
        // there wasn't a node in the output queue
        // so refill the output queue with the nodes from the input queue
        popped_node = load(&(p_queue->p_in_link));
        if (NULL != popped_node)
        {
            // take all of the nodes off of the input queue
            lockless_queue_node* p_actual = NULL;
            while (popped_node !=
                   (p_actual = compare_exchange(
                        (&p_queue->p_in_link), popped_node, NULL)))
            {
                popped_node = p_actual;
            }

            // reverse the nodes from the input queue
            lockless_queue_node* prev_node = NULL;
            lockless_queue_node* next_node = load(&(popped_node->p_link));
            while (NULL != next_node)
            {
                store(&(popped_node->p_link), prev_node);
                prev_node = popped_node;
                popped_node = next_node;
                next_node = load(&(next_node->p_link));
            }

            // move the nodes to the output queue
            store(&(p_queue->p_out_link), prev_node);
            store(&(popped_node->p_link), NULL);
        }
    }

    return popped_node;
} /* lockless_queue_pop */
