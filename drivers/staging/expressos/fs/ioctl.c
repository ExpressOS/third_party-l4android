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

#include "expressos.h"

#include <linux/ashmem.h>
#include <linux/file.h>
#include <linux/pagemap.h>

#include <asm-generic/ioctls.h>

long do_fcntl(int fd, unsigned int cmd, unsigned long arg,
              struct file *filp);

int expressos_ipc_ashmem_ioctl(int helper_pid, int fd, unsigned cmd, int arg0)
{
        int ret;
        mm_segment_t fs_save;
        struct expressos_venus_proc *proc;
        struct file *file;

        switch (cmd) {
                case ASHMEM_PIN:
                case ASHMEM_UNPIN:
                case ASHMEM_SET_NAME:
                case ASHMEM_GET_NAME:
                        arg0 = (int)expressos_ipc_shm_buf;
                        break;

                case ASHMEM_SET_SIZE:
                case ASHMEM_GET_SIZE:
                case ASHMEM_SET_PROT_MASK:
                case ASHMEM_GET_PROT_MASK:
                case ASHMEM_GET_PIN_STATUS:
                case ASHMEM_PURGE_ALL_CACHES:
                        break;

                default:
                        return -ENOSYS;
        }

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(file = expressos_venus_fget(proc, fd)))
                return -EBADF;

        fs_save = get_fs();
        set_fs(get_ds());
        ret = do_vfs_ioctl(file, -1, cmd, arg0);
        set_fs(fs_save);

        fput(file);
        return ret;

}

int expressos_ipc_ioctl(int helper_pid, int fd, unsigned cmd, int arg0)
{
        int ret;
        mm_segment_t fs_save;
        struct expressos_venus_proc *proc;
        struct file *file;

        switch (cmd) {
                case FIONREAD:
                        arg0 = (int)expressos_ipc_shm_buf;
                        break;

                default:
                        return -ENOTTY;
        }

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(file = expressos_venus_fget(proc, fd)))
                return -EBADF;

        fs_save = get_fs();
        set_fs(get_ds());
        ret = do_vfs_ioctl(file, -1, cmd, arg0);
        set_fs(fs_save);

        fput(file);
        return ret;
}

int expressos_ipc_fcntl64(int helper_pid, int fd, int cmd, int arg0)
{
        int ret;
        mm_segment_t fs_save;
        struct expressos_venus_proc *proc;
        struct file *file;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(file = expressos_venus_fget(proc, fd)))
                return -EBADF;

        fs_save = get_fs();
        set_fs(get_ds());
        ret = do_fcntl(-1, cmd, arg0, file);
        set_fs(fs_save);
        fput(file);

        return ret;
}
