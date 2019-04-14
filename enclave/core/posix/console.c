// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/fs.h>
#include <openenclave/internal/hostfs.h>
#include <openenclave/internal/print.h>
#include "common_macros.h"

int oe_initialize_console_devices(void)
{
    int ret = -1;
    oe_device_t* hostfs;
    oe_device_t* in = NULL;
    oe_device_t* out = NULL;
    oe_device_t* err = NULL;

    /* Get the hostfs singleton instance. */
    if (!(hostfs = oe_fs_get_hostfs()))
    {
        OE_TRACE_ERROR("oe_fs_get_hostfs failed");
        goto done;
    }

    /* Open stdin. */
    if (!(in = hostfs->ops.fs->open(hostfs, "/dev/stdin", OE_O_RDONLY, 0)))
    {
        OE_TRACE_ERROR("open stdin failed (in=%d)", in);
        goto done;
    }

    /* Open stdout. */
    if (!(out = hostfs->ops.fs->open(hostfs, "/dev/stdout", OE_O_WRONLY, 0)))
    {
        OE_TRACE_ERROR("open stdout failed (out=%d)", out);
        goto done;
    }

    /* Open stderr. */
    if (!(err = hostfs->ops.fs->open(hostfs, "/dev/stderr", OE_O_WRONLY, 0)))
    {
        OE_TRACE_ERROR("open stderr failed (err=%d)", err);
        goto done;
    }

    /* Set the stdin device. */
    if (!oe_set_fd_device(OE_STDIN_FILENO, in))
    {
        OE_TRACE_ERROR("Set the stdin device");
        goto done;
    }

    /* Set the stdout device. */
    if (!oe_set_fd_device(OE_STDOUT_FILENO, out))
    {
        OE_TRACE_ERROR("Set the stdout device");
        goto done;
    }

    /* Set the stderr device. */
    if (!oe_set_fd_device(OE_STDERR_FILENO, err))
    {
        OE_TRACE_ERROR("Set the stderr device");
        goto done;
    }

    in = NULL;
    out = NULL;
    err = NULL;
    ret = 0;

done:

    if (in)
        in->ops.base->close(in);

    if (out)
        out->ops.base->close(out);

    if (err)
        err->ops.base->close(err);

    return ret;
}
