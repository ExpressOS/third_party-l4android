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

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

static int proc_open_stat(struct inode *inode, struct file *filp);
static int proc_open_cmd(struct inode *inode, struct file *filp);
static int proc_write_cmd(struct file *filp, const char __user *ubuf, size_t count, loff_t *off);

static const struct file_operations proc_stat_fops = {
	.owner		= THIS_MODULE,
	.open		= proc_open_stat,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations proc_cmd_fops = {
        .owner          = THIS_MODULE,
        .open           = proc_open_cmd,
        .write          = proc_write_cmd,
        .release        = single_release,
};

struct proc_dir_entry *expressos_proc_ent;
int expressos_proc_init(void)
{
        struct proc_dir_entry *ent_stat, *ent_cmd;

        expressos_proc_ent = proc_mkdir("expressos", NULL);
        if (!expressos_proc_ent)
                return -ENOENT;

        ent_stat = proc_create("stat", 0, expressos_proc_ent, &proc_stat_fops);
        ent_cmd = proc_create("cmd", S_IWUSR, expressos_proc_ent, &proc_cmd_fops);

        if (!ent_stat || !ent_cmd)
                return -ENOENT;

        return 0;
}

void expressos_proc_destroy(void)
{
        remove_proc_entry("expressos", NULL);
}

static int proc_show_stat(struct seq_file *seq, void *v)
{
        expressos_ipc_dump_stat(seq);
        expressos_profiler_dump(seq);
        return 0;
}

static int proc_open_stat(struct inode *inode, struct file *filp)
{
        return single_open(filp, proc_show_stat, NULL);
}

static int proc_show_cmd(struct seq_file *seq, void *v)
{
        return 0;
}

static int proc_open_cmd(struct inode *inode, struct file *filp)
{
        return single_open(filp, proc_show_cmd, NULL);
}

static int proc_write_cmd(struct file *file, const char __user *ubuf, size_t count, loff_t *off)
{
        static const size_t MAX_WRITE_SIZE = 512;
        char buf[MAX_WRITE_SIZE];
        int cmd;

        if (count > MAX_WRITE_SIZE)
                count = MAX_WRITE_SIZE;

        if (copy_from_user(buf, ubuf, count))
                return -EFAULT;

        cmd = simple_strtoul(buf, NULL, 10);

        switch (cmd) {
                case EXPRESSOS_CMD_KICKSTART:
                        expressos_ipc_kickstart();
                        break;

                case EXPRESSOS_CMD_ENABLE_PROFILER:
                case EXPRESSOS_CMD_DISABLE_PROFILER:
                        break;

                default:
                        break;
        }
        return count;
}
