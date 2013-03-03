/*
 * Copyright (c) 2012-2013 University of Illinois at
 * Urbana-Champaign. All rights reserved.
 *
 * Developed by:
 *
 *     Haohui Mai
 *     University of Illinois at Urbana-Champaign
 *     http://haohui.me
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal with the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimers.
 *
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimers in the documentation and/or other materials
 *      provided with the distribution.
 *
 *    * Neither the names of University of Illinois at
 *      Urbana-Champaign, nor the names of its contributors may be
 *      used to endorse or promote products derived from this Software
 *      without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of
 * the GNU General Public License ("GPL") version 2 as published by
 * the Free Software Foundation.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS WITH THE SOFTWARE.
 */

#include "ipc-stubs.h"
#include "expressos.h"

void expressos_ipc_binder_write_read_async(
        int helper_pid, uint handle, void *buffer,
        uint size, uint bwr_write_size,
        uint patch_table_entries, uint patch_table_offset)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct expressos_venus_upcall *u;

        if (!expressos_ipc_valid_trunk(buffer, size)) {
                ret = -EFAULT;
                goto err;
        }

        if (!(proc = expressos_venus_find_proc(helper_pid))) {
                ret = -EINVAL;
                goto err;
        }

        u = expressos_venus_alloc_upcall(EXPRESSOS_VENUS_BINDER_WRITE_READ,
                                         sizeof(handle) + size +
                                         sizeof(struct expressos_venus_binder_write_read_in));
        if (!u) {
                ret = -ENOMEM;
                goto err;
        }

        u->async.handle                    = handle;
        u->async.bwr.buffer                = (unsigned long)buffer;
        u->async.bwr.payload_size          = size;
        u->async.bwr.bwr_write_size        = bwr_write_size;
        u->async.bwr.patch_table_entry_num = patch_table_entries;
        u->async.bwr.patch_table_offset    = patch_table_offset;
        memcpy(u->async.bwr.payload, buffer, size);

        ret = expressos_venus_upcall(proc, u);
        if (ret) {
                expressos_venus_free_upcall(u);
                goto err;
        }

        return;

err:
        expressos_ipc_return_2(expressos_op_binder_write_read_async, handle, ret);
        return;
}

int expressos_venus_downcall_binder_write_read(struct expressos_venus_proc *proc,
                                               const struct expressos_venus_downcall *d)
{
        int ret    = d->async.bwr.ret;
        void *dest = (void*)d->async.bwr.buffer;

        if (!expressos_ipc_valid_trunk(dest, d->async.bwr.payload_size))
                ret = -EFAULT;

        if (ret >= 0)
                memcpy(dest, d->async.bwr.payload, d->async.bwr.payload_size);

        expressos_ipc_return_6(expressos_op_binder_write_read_async,
                               d->async.handle, d->async.bwr.ret,
                               d->async.bwr.write_consumed,
                               d->async.bwr.read_consumed,
                               d->async.bwr.payload_size,
                               d->async.bwr.data_entries
                               );
        return 0;
}
