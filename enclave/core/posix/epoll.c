// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
// clang-format on

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/utils.h>
#include <openenclave/internal/array.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/epoll.h>
#include "common_macros.h"

int oe_epoll_create(int size)
{
    int ret = -1;
    oe_device_t* pepoll = NULL;
    oe_device_t* pdevice = NULL;

    pdevice = oe_get_devid_device(OE_DEVID_EPOLL);
    if ((pepoll = (*pdevice->ops.epoll->create)(pdevice, size)) == NULL)
    {
        OE_TRACE_ERROR("size = %d ", size);
        goto done;
    }
    ret = oe_assign_fd_device(pepoll);
    if (ret == -1)
    {
        OE_TRACE_ERROR("size = %d ", size);
        goto done;
    }

done:
    return ret;
}

int oe_epoll_create1(int flags)
{
    int ret = -1;
    oe_device_t* pepoll = NULL;
    oe_device_t* pdevice = NULL;

    pdevice = oe_get_devid_device(OE_DEVID_EPOLL);
    if ((pepoll = (*pdevice->ops.epoll->create1)(pdevice, flags)) == NULL)
    {
        OE_TRACE_ERROR("flags=%d oe_errno =%d ", flags, oe_errno);
        goto done;
    }
    ret = oe_assign_fd_device(pepoll);
    if (ret == -1)
    {
        OE_TRACE_ERROR("flags=%d oe_errno =%d ", flags, oe_errno);
        goto done;
    }

done:
    return ret;
}

int oe_epoll_ctl(int epfd, int op, int fd, struct oe_epoll_event* event)
{
    int ret = -1;
    oe_device_t* pepoll = oe_get_fd_device(epfd);
    oe_device_t* pdevice = oe_get_fd_device(fd);

    oe_errno = 0;
    /* Check parameters. */
    IF_TRUE_SET_ERRNO_JUMP(!pepoll || !pdevice, EINVAL, done);

    switch (op)
    {
        case OE_EPOLL_CTL_ADD:
        {
            IF_TRUE_SET_ERRNO_JUMP(
                pepoll->ops.epoll->ctl_add == NULL, EINVAL, done);
            ret = (*pepoll->ops.epoll->ctl_add)(epfd, fd, event);
            break;
        }
        case OE_EPOLL_CTL_DEL:
        {
            ret = (*pepoll->ops.epoll->ctl_del)(epfd, fd);
            break;
        }
        case OE_EPOLL_CTL_MOD:
        {
            ret = (*pepoll->ops.epoll->ctl_del)(epfd, fd);
            break;
        }
        default:
        {
            oe_errno = EINVAL;
            ret = -1;
            break;
        }
    }

done:
    if (ret == -1)
    {
        OE_TRACE_ERROR("op(%d) oe_errno =%d ", op, oe_errno);
    }
    return ret;
}

int oe_epoll_wait(
    int epfd,
    struct oe_epoll_event* events,
    int maxevents,
    int timeout)
{
    oe_device_t* pepoll = oe_get_fd_device(epfd);
    int ret = -1;
    bool has_host_wait =
        true; // false; // 2do. We need to figure out how to wait

    IF_TRUE_SET_ERRNO_JUMP(!pepoll, EINVAL, done);
    IF_TRUE_SET_ERRNO_JUMP(pepoll->ops.epoll->wait == NULL, EINVAL, done);

    // Start an outboard waiter if host involved
    // search polled device list for host involved  2Do
    if (has_host_wait)
    {
        ret = (*pepoll->ops.epoll->wait)(
            epfd, events, (size_t)maxevents, timeout);
        IF_TRUE_SET_ERRNO_JUMP(ret < 0, EINVAL, done);
    }

    // We check immediately because we might have gotten lucky and had stuff
    // come in immediately. If so we skip the wait
    ret = oe_get_epoll_events((uint64_t)epfd, (size_t)maxevents, events);
    if (ret == 0)
    {
        if (oe_wait_device_notification(timeout) < 0)
        {
            oe_errno = EPROTO;
            ret = -1;
            goto done;
        }
        ret = oe_get_epoll_events((uint64_t)epfd, (size_t)maxevents, events);
    }
done:
    return ret; // return the number of descriptors that have signalled
}

/* ATTN:IO: please remove this if it really not used. */
#if MAYBE
int oe_epoll_pwait(
    int epfd,
    struct epoll_event* events,
    int maxevents,
    int timeout,
    const sigset_t* ss)
{
    return -1;
}
#endif

static oe_cond_t poll_notification = OE_COND_INITIALIZER;
static oe_mutex_t poll_lock = OE_MUTEX_INITIALIZER;

#define NODE_CHUNK 256

struct _notification_node
{
    struct _oe_device_notifications notice;
    struct _notification_node* pnext;
};

struct _notification_node_chunk
{
    size_t maxnodes;
    size_t numnodes;
    struct _notification_node nodes[NODE_CHUNK];
    struct _notification_node_chunk* pnext;
};

#define ELEMENT_SIZE sizeof(struct _notification_node*)
#define CHUNK_SIZE 8
static oe_array_t _notify_arr = OE_ARRAY_INITIALIZER(ELEMENT_SIZE, CHUNK_SIZE);
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

OE_INLINE struct _notification_node** _table(void)
{
    return (struct _notification_node**)_notify_arr.data;
}

// This gets locked in outer levels

static struct _notification_node** _notification_list(uint64_t epoll_id)
{
    struct _notification_node** ret = NULL;

    if (epoll_id >= _notify_arr.size)
    {
        IF_TRUE_SET_ERRNO_JUMP(
            (oe_array_resize(&_notify_arr, epoll_id + 1) != 0), ENOMEM, done);
    }

    ret = _table() + epoll_id;

done:

    return ret;
}

//
// We allocate an array of notification_nodes whose roots are accessed by the
// array _notify_arr indexed by the epoll fd We allocate the nodes from chunks.
// Since the nodes are linked lists, we need to preserve addresses, so cannot
// use oe_realloc on the actual list nodes. So we allocate chunks, invalidate
// the
// ATTN:IO: seems like the previous sentence is incomplete.

static struct _notification_node_chunk* pdevice_notice_chunks = NULL;
static struct _notification_node_chunk* pdevice_notice_chunk_tail = NULL;

static struct _notification_node* _new_notification()
{
    struct _notification_node_chunk* pchunk;

    if (!pdevice_notice_chunk_tail)
    {
        // We never had a notice posted. Everything is null.
        pdevice_notice_chunks = (struct _notification_node_chunk*)oe_calloc(
            1, sizeof(struct _notification_node_chunk));
        // ATTN:IO: check return value of oe_calloc() for null.
        pdevice_notice_chunk_tail = pdevice_notice_chunks;
        pdevice_notice_chunk_tail->maxnodes = NODE_CHUNK;
        pdevice_notice_chunk_tail->numnodes = 1; // Because we are returning one
        pdevice_notice_chunk_tail->pnext = NULL;
        return &pdevice_notice_chunk_tail->nodes[0];
    }

    // We look for a node chunk with some room
    for (pchunk = pdevice_notice_chunks; pchunk != NULL; pchunk = pchunk->pnext)
    {
        if (pchunk->numnodes < pchunk->maxnodes)
        {
            break;
        }
    }

    // If we went through the entire list and the chunks are all full, we need a
    // new chunk. We expect this to happen very seldom we don't free chunks
    // until atend
    if (pchunk == NULL)
    {
        pdevice_notice_chunk_tail->pnext =
            (struct _notification_node_chunk*)oe_calloc(
                1, sizeof(struct _notification_node_chunk));
        pdevice_notice_chunk_tail = pdevice_notice_chunk_tail->pnext;
        pdevice_notice_chunk_tail->maxnodes = NODE_CHUNK;
        pdevice_notice_chunk_tail->numnodes = 1; // Because we are returning one
        pdevice_notice_chunk_tail->pnext = NULL;
        return &pdevice_notice_chunk_tail->nodes[0];
    }

    // Find a node . First on the top as the cheapest guess
    size_t nodeidx = pchunk->numnodes;
    while (nodeidx < pchunk->maxnodes)
    {
        if (pchunk->nodes[nodeidx].notice.event_mask == 0)
        {
            // We found one. Now its taken
            pchunk->numnodes++;
            return &pchunk->nodes[nodeidx];
        }
        nodeidx++;
    }

    // Find a node . Next lower half. This should find it or something is broken
    nodeidx = 0;
    while (nodeidx < pchunk->numnodes)
    {
        if (pchunk->nodes[nodeidx].notice.event_mask == 0)
        {
            // We found one
            pchunk->numnodes++;
            return &pchunk->nodes[nodeidx];
        }
        nodeidx++;
    }
    return NULL; // Should be an assert. We can't get here unless there is a bug
}

int oe_post_device_notifications(
    int num_notifications,
    struct _oe_device_notifications* notices)
{
    struct _notification_node** pplist = NULL;
    struct _notification_node* pnode = NULL;
    struct _notification_node* ptail = NULL;
    int locked = false;

    if (!notices)
    {
        // complain and throw something as notices are not allowed be null
        return -1;
    }

    oe_spin_lock(&_lock);
    locked = true;

    // We believe that all of the notifications in the list are going to the
    // same epoll.
    pplist = _notification_list(notices[0].epoll_fd);
    pnode = _new_notification();
    pnode->notice = notices[0];
    if (*pplist == NULL)
    {
        *pplist = pnode;
        ptail = pnode;
    }
    else
    {
        // Find the end of the list. This will almost certainly not be hit, but
        // it could be if we report more than once before epoll_wait returns.
        for (ptail = *pplist; ptail->pnext;)
        {
            if (!ptail->pnext)
            {
                break;
            }
            ptail = ptail->pnext;
        }
        ptail->pnext = pnode;
        ptail = pnode;
    }

    int i = 1;
    for (; i < num_notifications; i++)
    {
        pnode = _new_notification();

        pnode->notice = notices[i];
        ptail->pnext = pnode;
        ptail = ptail->pnext;
    }

    if (locked)
        oe_spin_unlock(&_lock);

    return 0;
}

// parms: epfd is the enclave fd of the epoll
//        maxevents is the number of events in the buffer
//        pevents is storage for <maxevents> events
//
// returns: 0 = no list.
//          >0 = returned length of the list
//          <0 = something bad happened.
//
//
int oe_get_epoll_events(
    uint64_t epfd,
    size_t maxevents,
    struct oe_epoll_event* pevents)

{
    oe_device_t* pepoll = oe_get_fd_device((int)epfd); // this limit checks fd
    struct _notification_node** pplist = NULL;
    struct _notification_node* plist = NULL;
    struct _notification_node* ptail = NULL;
    size_t numevents = 0;
    size_t i = 0;
    int locked = false;
    int ret = -1;

    if (epfd >= _notify_arr.size)
    {
        IF_TRUE_SET_ERRNO_JUMP(
            (oe_array_resize(&_notify_arr, epfd + 1) != 0), ENOMEM, done);
    }

    pplist = _table() + epfd;
    if (!*pplist)
    {
        // Not having notifications isn't an error
        ret = 0;
        goto done;
    }

    IF_TRUE_SET_ERRNO_JUMP((!pevents || maxevents < 1), EINVAL, done);

    oe_spin_lock(&_lock);
    locked = true;
    plist = *pplist;

    // Count the list.
    for (ptail = plist; ptail; ptail = ptail->pnext)
    {
        numevents++;
    }

    if (numevents > maxevents)
    {
        numevents = maxevents;
    }

    ptail = plist; // We take from the front and invalidate the nodes as we go.
                   // Then we put whats left onto the _notify_arr array
    for (i = 0; ptail && i < numevents; i++)
    {
        pevents[i].events = ptail->notice.event_mask;
        if ((pevents[i].data.u64 = (*pepoll->ops.epoll->geteventdata)(
                 pepoll, ptail->notice.list_idx)) == (uint64_t)-1)
        {
            oe_errno = EINVAL;
            OE_TRACE_ERROR("epfd=%ld oe_errno=%d", epfd, oe_errno);
            ret = -1;
            goto done;
        }
        ptail->notice.event_mask = 0; // Invalidate the node.
        ptail = ptail->pnext;
    }
    *pplist = ptail;
    if (locked)
        oe_spin_unlock(&_lock);

    ret = (int)numevents;
done:
    return ret;
}

//
// We accept a list of notifications so we don't get large number
// of handle notification calls in rapid succesion. This could raise needless
// synchronisaion issues. Instead, we send the list and notify the list, the
// push the doorbell
int oe_posix_polling_notify_ecall(
    oe_device_notifications_t* notifications,
    size_t num_notifications)
{
    int ret = -1;

    ret = oe_post_device_notifications((int)num_notifications, notifications);
    IF_TRUE_SET_ERRNO_JUMP(ret < 0, oe_errno, done);

    /* push the doorbell */
    oe_broadcast_device_notification();

    ret = 0;

done:
    return ret;
}

void oe_signal_device_notification(oe_device_t* pdevice, uint32_t event_mask)
{
    (void)pdevice;
    (void)event_mask;
}

void oe_broadcast_device_notification()
{
    oe_cond_broadcast(&poll_notification);
}

int oe_wait_device_notification(int timeout)
{
    (void)timeout;

    oe_mutex_lock(&poll_lock);
    oe_cond_wait(&poll_notification, &poll_lock);
    oe_mutex_unlock(&poll_lock);

    return 0;
}

void oe_clear_device_notification()
{
}
