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
#include <linux/pagemap.h>

#ifdef __ARCH_WANT_OLD_STAT
int cp_old_stat(struct kstat *stat, struct __old_kernel_stat __user * statbuf);
#endif

int cp_new_stat(struct kstat *stat, struct stat __user *statbuf);
long cp_new_stat64(struct kstat *stat, struct stat64 __user *statbuf);

static int get_stat_len(int type);
static int to_user_stat(int type, struct kstat *kstat_buf);
int expressos_fstat_helper(struct file *f, struct kstat *stat)
{
	return vfs_getattr(f->f_path.mnt, f->f_path.dentry, stat);
}

int expressos_ipc_fstat_combined(int helper_pid, int type, int fd, unsigned *stat_len)
{
        int err;
	struct kstat kstat_buf;
        struct expressos_venus_proc *proc;
        struct file *file;

        *stat_len = get_stat_len(type);
        if (!*stat_len)
                return -EINVAL;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(file = expressos_venus_fget(proc, fd)))
                return -EBADF;

        if ((err = expressos_fstat_helper(file, &kstat_buf))) {
                fput(file);
                return err;
        }

        err = to_user_stat(type, &kstat_buf);
        fput(file);
        return err;
}

int expressos_ipc_stat_combined(int helper_pid, int type, unsigned *stat_len)
{
        int err;
	struct kstat kstat_buf;
        struct expressos_venus_proc *proc;
        mm_segment_t fs_save;

        *stat_len = get_stat_len(type);
        if (!*stat_len)
                return -EINVAL;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        fs_save = get_fs();
        set_fs(get_ds());

        err = vfs_fstatat(AT_FDCWD, expressos_ipc_shm_buf, &kstat_buf,
                          type == EXPRESSOS_STAT_LSTAT64 ? AT_SYMLINK_NOFOLLOW : 0);
        set_fs(fs_save);

        if (err)
                return err;

        return to_user_stat(type, &kstat_buf);
}

static int get_stat_len(int type)
{
        BUG_ON(type >= EXPRESSOS_STAT_COUNT);
        switch (type) {

#ifdef __ARCH_WANT_OLD_STAT
                case EXPRESSOS_STAT_STAT:
                        return sizeof(struct __old_kernel_stat);
#endif

                case EXPRESSOS_STAT_NEWSTAT:
                        return sizeof(struct stat);

                case EXPRESSOS_STAT_STAT64:
                case EXPRESSOS_STAT_LSTAT64:
                        return sizeof(struct stat64);

                default:
                        return 0;
        }
}

static int to_user_stat(int type, struct kstat *kstat_buf)
{
        int err;
        mm_segment_t fs_save;
        fs_save = get_fs();
        set_fs(get_ds());

        switch (type) {

#ifdef __ARCH_WANT_OLD_STAT
                case EXPRESSOS_STAT_STAT:
                        err = cp_old_stat(kstat_buf, (struct __old_kernel_stat __user *)expressos_ipc_shm_buf);
                        break;
#endif

                case EXPRESSOS_STAT_NEWSTAT:
                        err = cp_new_stat(kstat_buf, (struct stat __user *)expressos_ipc_shm_buf);
                        break;

                case EXPRESSOS_STAT_STAT64:
                case EXPRESSOS_STAT_LSTAT64:
                        err = cp_new_stat64(kstat_buf, (struct stat64 __user *)expressos_ipc_shm_buf);
                        break;
                default:
                        err = -EINVAL;
                        break;
        }
        set_fs(fs_save);
        return err;
}
