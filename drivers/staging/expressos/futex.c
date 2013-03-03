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

void expressos_ipc_futex_wait(int helper_pid, uint handle, int op,
                              long uaddr, int val,
                              uint tv_sec, uint tv_nsec,
                              uint bitset)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct expressos_venus_upcall *u;
        struct timespec ts = {
                .tv_sec = tv_sec,
                .tv_nsec = tv_nsec,
        };

        if (!(proc = expressos_venus_find_proc(helper_pid))) {
                ret = -EINVAL;
                goto err;
        }

        u = expressos_venus_alloc_upcall(EXPRESSOS_VENUS_FUTEX_WAIT,
                                         sizeof(handle) +
                                         sizeof(struct expressos_venus_futex_wait_in));
        if (!u) {
                ret = -ENOMEM;
                goto err;
        }

        u->async.handle            = handle;
        u->async.futex_wait.op     = op;
        u->async.futex_wait.uaddr  = uaddr;
        u->async.futex_wait.val    = val;
        u->async.futex_wait.ts     = ts;
        u->async.futex_wait.bitset = bitset;

        ret = expressos_venus_upcall(proc, u);
        if (ret) {
                expressos_venus_free_upcall(u);
                goto err;
        }

        return;

err:
        expressos_ipc_return_2(expressos_op_futex_wait, handle, ret);
        return;
}

void expressos_ipc_futex_wake(int helper_pid, uint handle, int op,
                              long uaddr, uint bitset)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct expressos_venus_upcall *u;

        if (!(proc = expressos_venus_find_proc(helper_pid))) {
                ret = -EINVAL;
                goto err;
        }

        u = expressos_venus_alloc_upcall(EXPRESSOS_VENUS_FUTEX_WAIT,
                                         sizeof(handle) +
                                         sizeof(struct expressos_venus_futex_wake_in));
        if (!u) {
                ret = -ENOMEM;
                goto err;
        }

        u->async.handle            = handle;
        u->async.futex_wake.op     = op;
        u->async.futex_wake.uaddr  = uaddr;
        u->async.futex_wake.bitset = bitset;

        ret = expressos_venus_upcall(proc, u);
        if (ret) {
                expressos_venus_free_upcall(u);
                goto err;
        }

        return;

err:
        expressos_ipc_return_2(expressos_op_futex_wake, handle, ret);
        return;
}

int expressos_venus_downcall_futex_wait(struct expressos_venus_proc *proc,
                                        const struct expressos_venus_downcall *d)
{
        expressos_ipc_return_2(expressos_op_futex_wait,
                               d->async.handle, d->async.ret);
        return 0;
}

int expressos_venus_downcall_futex_wake(struct expressos_venus_proc *proc,
                                        const struct expressos_venus_downcall *d)
{
        expressos_ipc_return_2(expressos_op_futex_wake,
                               d->async.handle, d->async.ret);
        return 0;
}
