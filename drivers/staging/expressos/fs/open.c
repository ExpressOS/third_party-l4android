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

#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/security.h>
#include <linux/syscalls.h>

static long task_open(struct task_struct *target, const char *filename, int flags, int mode);
static int vfs_ftruncate(struct file *file, off_t length);

int expressos_ipc_open(int helper_pid, int flags, int mode)
{
        struct expressos_venus_proc *proc;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        return task_open(proc->task, expressos_ipc_shm_buf, flags, mode);
}

void expressos_ipc_close(int helper_pid, int fd)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct expressos_venus_upcall *u;

        if (!(proc = expressos_venus_find_proc(helper_pid))) {
                ret = -EINVAL;
                goto err;
        }

        u = expressos_venus_alloc_upcall(EXPRESSOS_VENUS_CLOSE,
                                         sizeof(struct expressos_venus_close_in));
        if (!u) {
                ret = -ENOMEM;
                goto err;
        }

        u->close.fd = fd;
        ret = expressos_venus_upcall(proc, u);
        if (ret) {
                expressos_venus_free_upcall(u);
                goto err;
        }

        return;

err:
        expressos_ipc_return_1(expressos_op_close, ret);
        return;
}

int expressos_venus_downcall_close(struct expressos_venus_proc *proc,
                                   const struct expressos_venus_downcall *d)
{
        expressos_ipc_return_1(expressos_op_close, d->ret);
        return 0;
}

int expressos_ipc_open_and_get_size_async(int helper_pid, const void *filename,
                                          int flags, int mode, unsigned *file_size)
{
        int fd;
        struct expressos_venus_proc *proc;
        struct file *file;
        struct kstat kstat_buf;

        *file_size = 0;
        if (!expressos_ipc_valid_ptr(filename))
                return -EFAULT;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if ((fd = task_open(proc->task, filename, flags, mode)) < 0)
                return fd;

        if (!(file = expressos_venus_fget(proc, fd)))
                return -ENOENT;

        if (!expressos_fstat_helper(file, &kstat_buf))
                *file_size = kstat_buf.size;

        fput(file);

        return fd;
}

int expressos_ipc_open_and_read_pages_async(int helper_pid, void *data,
                                            int npages,
                                            int flags, int mode,
                                            unsigned *file_size)
{
        int fd;
        loff_t pos = 0;
        struct expressos_venus_proc *proc;
        struct file *file;
        struct kstat kstat_buf;
        mm_segment_t fs_save;

        *file_size = 0;
        if (!expressos_ipc_valid_trunk(data, npages * PAGE_SIZE))
                return -EFAULT;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if ((fd = task_open(proc->task, data, flags, mode)) < 0)
                return fd;

        if (!(file = expressos_venus_fget(proc, fd)))
                return -ENOENT;

        if (!expressos_fstat_helper(file, &kstat_buf))
                *file_size = kstat_buf.size;

        if (*file_size >= npages * PAGE_SIZE) {
                fs_save = get_fs();
                set_fs(get_ds());
                vfs_read(file, data, npages * PAGE_SIZE, &pos);
                set_fs(fs_save);
        } else if (*file_size != 0) {
                fd = -EINVAL;
        }

        fput(file);
        return fd;
}

int expressos_ipc_access_async(int helper_pid, const void *filename, int mode)
{
        return sys_faccessat(AT_FDCWD, filename, mode);
}

int expressos_ipc_ftruncate(int helper_pid, int fd, int length)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct file *file;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(file = expressos_venus_fget(proc, fd)))
                return -EBADF;

        ret = vfs_ftruncate(file, length);
        fput(file);

        return ret;
}

void expressos_ipc_pipe(int helper_pid, int *read_pipe, int *write_pipe)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct expressos_venus_upcall *u;

        if (!(proc = expressos_venus_find_proc(helper_pid))) {
                ret = -EINVAL;
                goto err;
        }

        if (!(u = expressos_venus_alloc_upcall(EXPRESSOS_VENUS_PIPE, 0))) {
                ret = -ENOMEM;
                goto err;
        }

        ret = expressos_venus_upcall(proc, u);
        if (ret) {
                expressos_venus_free_upcall(u);
                goto err;
        }

        return;
err:
        expressos_ipc_return_1(expressos_op_pipe, ret);
        return;
}

int expressos_venus_downcall_pipe(struct expressos_venus_proc *proc,
                                  const struct expressos_venus_downcall *d)
{
        if (d->pipe.ret >= 0)
                expressos_ipc_return_3(expressos_op_pipe, d->pipe.ret,
                                       d->pipe.read_pipe, d->pipe.write_pipe);
        else
                expressos_ipc_return_1(expressos_op_pipe, d->pipe.ret);

        return 0;
}


static int task_get_unused_fd_flags(struct task_struct *task, int flags)
{
	struct files_struct *files = task->files;
	int fd, error;
	struct fdtable *fdt;
	unsigned long rlim_cur;
	unsigned long irqs;

	if (files == NULL)
		return -ESRCH;

	error = -EMFILE;
	spin_lock(&files->file_lock);

repeat:
	fdt = files_fdtable(files);
	fd = find_next_zero_bit(fdt->open_fds->fds_bits, fdt->max_fds,
				files->next_fd);

	/*
	 * N.B. For clone tasks sharing a files structure, this test
	 * will limit the total number of files that can be opened.
	 */
	rlim_cur = 0;
	if (lock_task_sighand(task, &irqs)) {
		rlim_cur = task->signal->rlim[RLIMIT_NOFILE].rlim_cur;
		unlock_task_sighand(task, &irqs);
	}
	if (fd >= rlim_cur)
		goto out;

	/* Do we need to expand the fd array or fd set?  */
	error = expand_files(files, fd);
	if (error < 0)
		goto out;

	if (error) {
		/*
		 * If we needed to expand the fs array we
		 * might have blocked - try again.
		 */
		error = -EMFILE;
		goto repeat;
	}

	FD_SET(fd, fdt->open_fds);
	if (flags & O_CLOEXEC)
		FD_SET(fd, fdt->close_on_exec);
	else
		FD_CLR(fd, fdt->close_on_exec);
	files->next_fd = fd + 1;
#if 1
	/* Sanity check */
	if (fdt->fd[fd] != NULL) {
		printk(KERN_WARNING "get_unused_fd: slot %d not NULL!\n", fd);
		fdt->fd[fd] = NULL;
	}
#endif
	error = fd;

out:
	spin_unlock(&files->file_lock);
	return error;
}

/*
 * copied from fd_install
 */
static void task_fd_install(
	struct task_struct *target, unsigned int fd, struct file *file)
{
	struct files_struct *files = target->files;
	struct fdtable *fdt;

	if (files == NULL)
		return;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	BUG_ON(fdt->fd[fd] != NULL);
	rcu_assign_pointer(fdt->fd[fd], file);
	spin_unlock(&files->file_lock);
}

static long task_open(struct task_struct *target, const char *filename, int flags, int mode)
{
        struct file *f = filp_open(filename, flags, mode);
        int target_fd;

        if (IS_ERR(f))
                return PTR_ERR(f);

        target_fd = task_get_unused_fd_flags(target, flags);
        task_fd_install(target, target_fd, f);
        return target_fd;
}

static int vfs_ftruncate(struct file *file, off_t length)
{
        struct dentry *dentry;
        struct inode *inode;
        int small = 1;
        int error = 0;

        /* explicitly opened as large or we are on 64-bit box */
        if (file->f_flags & O_LARGEFILE)
                small = 0;

        dentry = file->f_path.dentry;
        inode = dentry->d_inode;
        error = -EINVAL;
        if (!S_ISREG(inode->i_mode) || !(file->f_mode & FMODE_WRITE))
                goto out_putf;

        error = -EINVAL;
        /* Cannot ftruncate over 2^31 bytes without large file support */
        if (small && length > MAX_NON_LFS)
                goto out_putf;

        error = -EPERM;


        error = locks_verify_truncate(inode, file, length);
        if (!error)
                error = security_path_truncate(&file->f_path);
        if (!error)
                error = do_truncate(dentry, length, ATTR_MTIME|ATTR_CTIME, file);

out_putf:
        return error;
}
