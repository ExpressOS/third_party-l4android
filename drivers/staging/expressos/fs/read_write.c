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
#include <expressos/linux.h>

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/pagemap.h>

enum {
        VFS_OP_READ,
        VFS_OP_WRITE,
};

static int vfs_read_write(int op, int helper_pid, void *data,
                          int fd, int count, unsigned *pos);

int expressos_ipc_vfs_read(int helper_pid, int fd, int count, unsigned *pos)
{
        if (count > EXPRESSOS_IPC_SYNC_CALL_BUF_SIZE)
                count = EXPRESSOS_IPC_SYNC_CALL_BUF_SIZE;

        return vfs_read_write(VFS_OP_READ, helper_pid, expressos_ipc_shm_buf,
                              fd, count, pos);
}

int expressos_ipc_vfs_read_async(int helper_pid, void *data, int fd,
                                 int count, unsigned *pos)
{
        if (!expressos_ipc_valid_trunk(data, count))
                return -EFAULT;

        return vfs_read_write(VFS_OP_READ, helper_pid, data,
                              fd, count, pos);
}

int expressos_ipc_vfs_write_async(int helper_pid, void *data, int fd,
                                  int count, unsigned *pos)
{
        if (!expressos_ipc_valid_trunk(data, count))
                return -EFAULT;

        return vfs_read_write(VFS_OP_WRITE, helper_pid, data,
                              fd, count, pos);
}

int expressos_ipc_scatter_write_page_async(int helper_pid, int fd,
                                           int page_count, const void *data)
{
        struct expressos_venus_proc *proc;
        struct file *file;
        mm_segment_t fs_save;
        int ret, i;

        const int *pg_offs = (const int*)data;
        const char *blob   = (const char*)(pg_offs + page_count);

        if (!expressos_ipc_valid_ptr(pg_offs)
            || !expressos_ipc_valid_trunk(blob, page_count * PAGE_SIZE))
                return -EFAULT;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(file = expressos_venus_fget(proc, fd)))
                return -EBADF;

        fs_save = get_fs();
        set_fs(get_ds());

        i = 0;
        while (i < page_count) {
                int j = i + 1;
                loff_t pos = pg_offs[i] * PAGE_SIZE;

                /*
                 * Consolidate write requests.
                 */
                while (j < page_count && pg_offs[j] == pg_offs[i] + (j - i))
                        ++j;

                ret = vfs_write(file, blob + i * PAGE_SIZE,
                                (j - i) * PAGE_SIZE, &pos);

                if (ret < 0)
                        printk(KERN_WARNING "expressos_ipc_flush_pages_async:"
                               "failed to write to pgoffset %d, fd=%d, ret=%d\n",
                               pg_offs[i], fd, ret);

                i = j;
        }

        set_fs(fs_save);
        fput(file);

        return 0;
}

static int vfs_read_write(int op, int helper_pid, void *data, int fd, int count, unsigned *pos)
{
        struct expressos_venus_proc *proc;
        struct file *file;
        mm_segment_t fs_save;
        int ret;
        loff_t p = *pos;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(file = expressos_venus_fget(proc, fd)))
                return -EBADF;

        fs_save = get_fs();
        set_fs(get_ds());

        if (op == VFS_OP_READ)
                ret = vfs_read(file, data, count, &p);
        else
                ret = vfs_write(file, data, count, &p);

        *pos = p;
        set_fs(fs_save);
        fput(file);

        return ret;

}
