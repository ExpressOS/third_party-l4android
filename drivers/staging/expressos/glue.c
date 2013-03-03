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

#include <linux/module.h>

#include <l4/re/c/mem_alloc.h>
#include <l4/re/c/rm.h>
#include <l4/re/c/util/cap_alloc.h>

l4re_ds_t expressos_ipc_shm_ds;
static void *ipc_buf;

int expressos_ipc_buffer_init(void **ipc_shm_buf, unsigned long buf_size)
{
        expressos_ipc_shm_ds = l4re_util_cap_alloc();

        if (l4_is_invalid_cap(expressos_ipc_shm_ds))
                return -ENOMEM;

        if (l4re_ma_alloc(buf_size, expressos_ipc_shm_ds, L4RE_MA_SUPER_PAGES))
                return -ENOMEM;

        if (l4re_rm_attach(ipc_shm_buf, buf_size,
                           L4RE_RM_SEARCH_ADDR, expressos_ipc_shm_ds, 0,
                           L4_SUPERPAGESHIFT))
                return -EPERM;

        ipc_buf = *ipc_shm_buf;
        return 0;
}

void expressos_ipc_buffer_destroy(void)
{
        l4re_rm_detach(ipc_buf);
        l4re_ma_free(expressos_ipc_shm_ds);
        l4re_util_cap_free(expressos_ipc_shm_ds);
}

EXPORT_SYMBOL(expressos_ipc_buffer_init);
EXPORT_SYMBOL(expressos_ipc_buffer_destroy);
EXPORT_SYMBOL(expressos_ipc_shm_ds);
