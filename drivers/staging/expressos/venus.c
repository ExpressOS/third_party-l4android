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

#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

struct expressos_venus_msg {
        struct list_head list;
        struct expressos_venus_upcall *upcall;
};

static struct {
        struct list_head list;
        spinlock_t lock;
} helpers;

static int handle_message(struct expressos_venus_proc *proc, const char *msg);

static int venus_write(struct expressos_venus_proc *proc, void __user *buffer,
                       unsigned long size, unsigned long *consumed);

static int venus_read(struct expressos_venus_proc *proc, void __user *buffer,
                       unsigned long size, unsigned long *consumed);

static long venus_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
        int ret = 0;
        unsigned size = _IOC_SIZE(cmd);
        struct expressos_venus_write_read wr;
        void __user *ubuf = (void __user*)arg;
        struct expressos_venus_proc *proc = filp->private_data;

        if (cmd != EXPRESSOS_VENUS_WRITE_READ || size != sizeof(wr))
                return -EINVAL;

        if (copy_from_user(&wr, ubuf, sizeof(wr)))
                return -EFAULT;

        if (wr.write_size > 0) {
                ret = venus_write(proc, (void __user *)wr.write_buffer,
                                  wr.write_size, &wr.write_consumed);
                if (ret < 0) {
                        wr.read_consumed = 0;
                        if (copy_to_user(ubuf, &wr, sizeof(wr)))
                                ret = -EFAULT;

                        return ret;
                }
        }

        if (wr.read_size > 0) {
                ret = venus_read(proc, (void __user *)wr.read_buffer,
                                 wr.read_size, &wr.read_consumed);
                if (ret < 0) {
                        if (copy_to_user(ubuf, &wr, sizeof(wr)))
                                ret = -EFAULT;

                        return ret;
                }
        }

        if (copy_to_user(ubuf, &wr, sizeof(wr)))
                ret = -EFAULT;

        return ret;
}

/*
 * Read downcall message from venus.
 *
 */
static int venus_write(struct expressos_venus_proc *proc, void __user *buffer,
                       unsigned long size, unsigned long *consumed)
{
        int ret = 0;
        struct expressos_venus_hdr hdr;
        char *msg;
        unsigned msg_size;

        char __user *ptr = buffer + *consumed;
        char __user *end = buffer + size;

        while (ptr < end) {
                if (copy_from_user(&hdr, ptr, sizeof(hdr)))
                        return -EFAULT;

                msg_size = sizeof(hdr) + hdr.payload_size;
                msg = kmalloc(msg_size, GFP_KERNEL);
                if (!msg)
                        return -ENOMEM;

                if (copy_from_user(msg, ptr, msg_size)) {
                        kfree(msg);
                        return -EFAULT;
                }

                *consumed += msg_size;
                ptr += msg_size;

                ret = handle_message(proc, msg);
                kfree(msg);

                if (ret)
                        return ret;
        }
        return 0;
}

static int venus_read(struct expressos_venus_proc *proc, void __user *buffer,
                       unsigned long size, unsigned long *consumed)
{
        int ret = 0;
        unsigned long flags;
        struct expressos_venus_msg *msg;
        char __user *ptr = buffer + *consumed;
        char __user *end = buffer + size;

retry:
        ret = wait_event_interruptible(proc->wait, !list_empty(&proc->upcalls));
        if (ret)
                return ret;

        spin_lock_irqsave(&proc->lock, flags);
        if (list_empty(&proc->upcalls)) {
                spin_unlock_irqrestore(&proc->lock, flags);
                goto retry;
        }

        while (ptr < end && !list_empty(&proc->upcalls)) {
                unsigned msg_size;
                msg = list_entry(proc->upcalls.next, struct expressos_venus_msg,
                                 list);
                msg_size = sizeof(struct expressos_venus_hdr)
                                + msg->upcall->hdr.payload_size;
                if ((void __user *)ptr == buffer && msg_size > size) {
                        ret = -ENOMEM;
                        goto out;
                }

                spin_unlock_irqrestore(&proc->lock, flags);
                if (copy_to_user(ptr, msg->upcall, msg_size)) {
                        ret = -EFAULT;
                        goto out_unlocked;
                }

                ptr += msg_size;
                *consumed += msg_size;

                expressos_venus_free_upcall(msg->upcall);
                spin_lock_irqsave(&proc->lock, flags);
                list_del(&msg->list);
                kfree(msg);
        }

out:
        spin_unlock_irqrestore(&proc->lock, flags);
out_unlocked:
        return ret;
}

static int venus_open(struct inode *nodp, struct file *filp)
{
        struct expressos_venus_proc *proc = kzalloc(sizeof(struct expressos_venus_proc), GFP_KERNEL);
        if (!proc)
                return -ENOMEM;

        init_waitqueue_head(&proc->wait);
        INIT_LIST_HEAD(&proc->upcalls);
        spin_lock_init(&proc->lock);

        filp->private_data = proc;
        return 0;
}

static int venus_release(struct inode *nodp, struct file *filp)
{
	struct expressos_venus_proc *proc = filp->private_data;
        kfree(proc);
        filp->private_data = NULL;

	return 0;
}

static int handle_message(struct expressos_venus_proc *proc, const char *msg)
{
        const struct expressos_venus_downcall *d = (const struct expressos_venus_downcall*)msg;

        switch (d->hdr.opcode) {
                case EXPRESSOS_VENUS_REGISTER_HELPER:
                        return expressos_venus_downcall_register_helper(proc, d);
                case EXPRESSOS_VENUS_CLOSE:
                        return expressos_venus_downcall_close(proc, d);
                case EXPRESSOS_VENUS_PIPE:
                        return expressos_venus_downcall_pipe(proc, d);
                case EXPRESSOS_VENUS_SOCKET:
                        return expressos_venus_downcall_socket(proc, d);
                case EXPRESSOS_VENUS_POLL:
                        return expressos_venus_downcall_poll(proc, d);
                case EXPRESSOS_VENUS_BINDER_WRITE_READ:
                        return expressos_venus_downcall_binder_write_read(proc, d);
                case EXPRESSOS_VENUS_ALIEN_MMAP2:
                        return expressos_venus_downcall_alien_mmap2(proc, d);
                case EXPRESSOS_VENUS_FUTEX_WAIT:
                        return expressos_venus_downcall_futex_wait(proc, d);
                case EXPRESSOS_VENUS_FUTEX_WAKE:
                        return expressos_venus_downcall_futex_wake(proc, d);

                default:
                        printk(KERN_WARNING "expressos-venus: unknown downcall %d\n", d->hdr.opcode);
                        break;
        }
        return 0;
}

static const struct file_operations venus_fops = {
	.owner = THIS_MODULE,
        .open = venus_open,
	.unlocked_ioctl = venus_ioctl,
        .release = venus_release,
};

static struct miscdevice venus_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "expressos",
	.fops = &venus_fops
};

int expressos_venus_init(void)
{
        spin_lock_init(&helpers.lock);
        INIT_LIST_HEAD(&helpers.list);
        misc_register(&venus_miscdev);
        return 0;
}

void expressos_venus_destroy(void)
{
        misc_deregister(&venus_miscdev);
}

int expressos_venus_downcall_register_helper(struct expressos_venus_proc *proc,
                                             const struct expressos_venus_downcall *d)
{
        unsigned long flags;
        const struct expressos_venus_register_helper_out *p = &d->register_helper;

        proc->available              = 1;
        proc->task                   = current;
        proc->pid                    = task_tgid_vnr(current);
        proc->binder_vm_start        = p->binder_vm_start;
        proc->android_workspace_fd   = p->workspace_fd;
        proc->android_workspace_size = p->workspace_size;

        spin_lock_irqsave(&helpers.lock, flags);
        list_add_tail(&proc->list, &helpers.list);
        spin_unlock_irqrestore(&helpers.lock, flags);

        return 0;
}

void expressos_ipc_take_helper(int *helper_pid, unsigned *vm_start,
                               int *workspace_fd, unsigned *workspace_size)
{
        struct list_head *lh;
        struct expressos_venus_proc *e = NULL;
        unsigned long flags;

        spin_lock_irqsave(&helpers.lock, flags);

        list_for_each(lh, &helpers.list) {
                e = list_entry(lh, struct expressos_venus_proc, list);
                if (e->available)
                        break;
        }

        if (e && e->available) {
                *helper_pid     = e->pid;
                *vm_start       = e->binder_vm_start;
                *workspace_fd   = e->android_workspace_fd;
                *workspace_size = e->android_workspace_size;
                e->available    = 0;
        } else {
                *helper_pid     = 0;
        }

        spin_unlock_irqrestore(&helpers.lock, flags);
}

void expressos_ipc_write_app_info(int helper_pid, int length)
{
        struct expressos_venus_proc *proc;
        struct file *filp;
        char buf[256];
        loff_t pos;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return;

        snprintf(buf, sizeof(buf), "/data/expressos/app_info-%d", helper_pid);

        filp = filp_open(buf, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IRGRP | S_IROTH);
        if (!filp)
                return;

        pos = 0;
        vfs_write(filp, expressos_ipc_shm_buf, length, &pos);
        filp_close(filp, NULL);
}

struct expressos_venus_proc *expressos_venus_find_proc(pid_t pid)
{
        struct list_head *lh;
        struct expressos_venus_proc *p = NULL;
        unsigned long flags;
        int found = 0;

        spin_lock_irqsave(&helpers.lock, flags);

        list_for_each(lh, &helpers.list) {
                p = list_entry(lh, struct expressos_venus_proc, list);
                if (p->pid == pid) {
                        found = 1;
                        break;
                }
        }

        spin_unlock_irqrestore(&helpers.lock, flags);
        return found ? p : NULL;
}

struct expressos_venus_upcall *expressos_venus_alloc_upcall(int opcode, unsigned payload_size)
{
        size_t s = sizeof(struct expressos_venus_hdr) + payload_size;
        struct expressos_venus_upcall *u = kmalloc(s, GFP_KERNEL);
        if (!u)
                return NULL;

        u->hdr.opcode = opcode;
        u->hdr.payload_size = payload_size;

        return u;
}

void expressos_venus_free_upcall(struct expressos_venus_upcall *u)
{
        kfree(u);
}

int expressos_venus_upcall(struct expressos_venus_proc *proc,
                           struct expressos_venus_upcall *u)
{
        unsigned long flags;
        struct expressos_venus_msg *msg;
        msg = kmalloc(sizeof(struct expressos_venus_msg), GFP_KERNEL);

        if (!msg)
                return -ENOMEM;

        msg->upcall = u;

        spin_lock_irqsave(&proc->lock, flags);
        list_add_tail(&msg->list, &proc->upcalls);
        spin_unlock_irqrestore(&proc->lock, flags);

        wake_up_interruptible(&proc->wait);
        return 0;
}

static struct file *task_fget(struct task_struct *task, unsigned int fd)
{
        struct file *file;
        struct files_struct *files;

        BUG_ON(!task || !task->files);
        files = task->files;

        rcu_read_lock();
        file = fcheck_files(files, fd);
        if (file) {
                /* File object ref couldn't be taken */
                if (file->f_mode & FMODE_PATH ||
                    !atomic_long_inc_not_zero(&file->f_count))
                        file = NULL;
        }
        rcu_read_unlock();

        return file;
}

struct file *expressos_venus_fget(struct expressos_venus_proc *proc, int fd)
{
        return task_fget(proc->task, fd);
}

int sock_is_sock_file(struct file *file);
struct socket *expressos_venus_get_sock(struct expressos_venus_proc *proc, int fd, int *err)
{
        struct file *file = expressos_venus_fget(proc, fd);
        if (!file) {
                *err = -EBADF;
                return NULL;
        }

        if (!sock_is_sock_file(file)) {
                *err = -ENOTSOCK;
                fput(file);
                return NULL;
        }

        return (struct socket *)file->private_data;
}
