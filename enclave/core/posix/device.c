// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/array.h>
#include <openenclave/internal/device.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include "common_macros.h"

#define ELEMENT_SIZE (sizeof(oe_device_t*))
#define CHUNK_SIZE ((size_t)8)

static oe_array_t _dev_arr = OE_ARRAY_INITIALIZER(ELEMENT_SIZE, CHUNK_SIZE);
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
static bool _initialized = false;

OE_INLINE oe_device_t** _table(void)
{
    return (oe_device_t**)_dev_arr.data;
}

OE_INLINE size_t _table_size(void)
{
    return _dev_arr.size;
}

static void _free_table(void)
{
    oe_array_free(&_dev_arr);
}

static int _init_table()
{
    if (_initialized == false)
    {
        oe_spin_lock(&_lock);
        {
            if (_initialized == false)
            {
                if (oe_array_resize(&_dev_arr, CHUNK_SIZE) != 0)
                {
                    oe_assert("_init_table()" == NULL);
                    oe_abort();
                }

                oe_atexit(_free_table);
                _initialized = true;
            }
        }
        oe_spin_unlock(&_lock);
    }

    return 0;
}

uint64_t oe_allocate_devid(uint64_t devid)
{
    uint64_t ret = OE_DEVID_NULL;
    bool locked = false;

    IF_TRUE_SET_ERRNO_JUMP((!_initialized && _init_table() != 0), ENOMEM, done);

    oe_spin_lock(&_lock);
    locked = true;

    if (devid >= _dev_arr.size)
    {
        IF_TRUE_SET_ERRNO_JUMP(
            (oe_array_resize(&_dev_arr, devid + 1) != 0), ENOMEM, done);
    }

    IF_TRUE_SET_ERRNO_JUMP(_table()[devid] != NULL, EADDRINUSE, done);
    ret = devid;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_release_devid(uint64_t devid)
{
    int ret = -1;
    bool locked = false;

    IF_TRUE_SET_ERRNO_JUMP(!_initialized && _init_table() != 0, ENOMEM, done);
    oe_spin_lock(&_lock);
    locked = true;

    IF_TRUE_SET_ERRNO_JUMP((devid >= _dev_arr.size), EINVAL, done);

    IF_TRUE_SET_ERRNO_JUMP((_table()[devid] == NULL), EINVAL, done);

    _table()[devid] = NULL;

    ret = 0;

done:

    if (locked)
        oe_spin_unlock(&_lock);

    return ret;
}

int oe_set_devid_device(uint64_t devid, oe_device_t* device)
{
    int ret = -1;

    IF_TRUE_SET_ERRNO_JUMP(devid > _table_size(), EINVAL, done);
    IF_TRUE_SET_ERRNO_JUMP(_table()[devid] != NULL, EADDRINUSE, done);

    _table()[devid] = device;

    ret = 0;

done:
    return ret;
}

oe_device_t* oe_get_devid_device(uint64_t devid)
{
    oe_device_t* ret = NULL;

    IF_TRUE_SET_ERRNO_JUMP(devid >= _table_size(), EINVAL, done);
    ret = _table()[devid];

done:
    return ret;
}

int oe_remove_device(uint64_t devid)
{
    int ret = -1;
    int retval = -1;
    oe_device_t* device = NULL;

    device = oe_get_devid_device(devid);
    if (!device)
    {
        OE_TRACE_ERROR("no device found devid(%d)", devid);
        goto done;
    }

    IF_TRUE_SET_ERRNO_JUMP(device->ops.base->shutdown == NULL, EINVAL, done);

    if ((retval = (*device->ops.base->shutdown)(device)) != 0)
    {
        OE_TRACE_ERROR("devid = %ld retval = %d", devid, retval);
        goto done;
    }

    ret = 0;

done:
    return ret;
}

ssize_t oe_read(int fd, void* buf, size_t count)
{
    ssize_t ret = -1;
    oe_device_t* device = oe_get_fd_device(fd);
    ssize_t n;

    if (!device)
    {
        OE_TRACE_ERROR("no device found fd=%d", fd);
        goto done;
    }

    IF_TRUE_SET_ERRNO_JUMP(device->ops.base->read == NULL, EINVAL, done);

    // The action routine sets errno
    if ((n = (*device->ops.base->read)(device, buf, count)) < 0)
    {
        OE_TRACE_ERROR("fd = %d n = %d", fd, n);
        goto done;
    }

    ret = n;

done:
    return ret;
}

ssize_t oe_write(int fd, const void* buf, size_t count)
{
    ssize_t ret = -1;
    oe_device_t* device = oe_get_fd_device(fd);

    OE_TRACE_VERBOSE("fd =%d device=%p", fd, device);
    IF_TRUE_SET_ERRNO_JUMP(!device, EBADF, done);

    IF_TRUE_SET_ERRNO_JUMP(device->ops.base->write == NULL, EINVAL, done);

    // The action routine sets errno
    ret = (*device->ops.base->write)(device, buf, count);

done:
    return ret;
}

int oe_close(int fd)
{
    int ret = -1;
    int retval = -1;
    oe_device_t* device = oe_get_fd_device(fd);

    if (!device)
    {
        OE_TRACE_ERROR("no device found for fd=%d", fd);
        goto done;
    }

    IF_TRUE_SET_ERRNO_JUMP(device->ops.base->close == NULL, EINVAL, done);

    if ((retval = (*device->ops.base->close)(device)) != 0)
    {
        OE_TRACE_ERROR("fd =%d retval=%d", fd, retval);
        goto done;
    }

    oe_release_fd(fd);

    ret = 0;

done:
    return ret;
}

int __oe_fcntl_va(int fd, int cmd, oe_va_list ap)
{
    int ret = -1;
    oe_device_t* device = oe_get_fd_device(fd);
    int arg;

    if (!device)
    {
        OE_TRACE_ERROR("no device found fd=%d", fd);
        goto done;
    }

    IF_TRUE_SET_ERRNO_JUMP(device->ops.base->fcntl == NULL, EINVAL, done);

    arg = oe_va_arg(ap, int);

    ret = (*device->ops.base->fcntl)(device, cmd, arg);

done:
    return ret;
}

int oe_ioctl_va(int fd, unsigned long request, oe_va_list ap)
{
    int ret = -1;

    switch (fd)
    {
        case OE_STDIN_FILENO:
        case OE_STDERR_FILENO:
        case OE_STDOUT_FILENO:
        {
            static const unsigned long _TIOCGWINSZ = 0x5413;

            if (request == _TIOCGWINSZ)
            {
                struct winsize
                {
                    unsigned short int ws_row;
                    unsigned short int ws_col;
                    unsigned short int ws_xpixel;
                    unsigned short int ws_ypixel;
                };
                struct winsize* p;

                p = oe_va_arg(ap, struct winsize*);

                if (!p)
                {
                    OE_TRACE_ERROR("fd=%d oe_va_arg failed", fd);
                    goto done;
                }

                p->ws_row = 24;
                p->ws_col = 80;
                p->ws_xpixel = 0;
                p->ws_ypixel = 0;

                ret = 0;
                goto done;
            }

            ret = -1;
            OE_TRACE_ERROR("fd=%d", fd);
            goto done;
        }
        default:
        {
            oe_device_t* pdevice = oe_get_fd_device(fd);

            if (!pdevice)
            {
                OE_TRACE_ERROR("no device found fd=%d", fd);
                ret = -1;
                goto done;
            }

            if (pdevice->ops.base->ioctl == NULL)
            {
                oe_errno = EINVAL;
                OE_TRACE_ERROR("fd=%d oe_errno =%d ", fd, oe_errno);
                ret = -1;
                goto done;
            }

            // The action routine sets errno
            ret = (*pdevice->ops.base->ioctl)(pdevice, request, ap);
            goto done;
        }
    }

done:
    return ret;
}

int oe_ioctl(int fd, unsigned long request, ...)
{
    oe_va_list ap;
    oe_va_start(ap, request);
    int r = oe_ioctl_va(fd, request, ap);
    oe_va_end(ap);
    return r;
}
