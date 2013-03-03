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

#ifndef LINUX_EXPRESSOS_H_
#define LINUX_EXPRESSOS_H_

#include <expressos/venus.h>

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include <l4/re/c/dataspace.h>
#include <l4/sys/utcb.h>

struct kstat;
struct seq_file;

struct expressos_venus_proc {
        struct list_head    list;
        pid_t               pid;
        int                 available;
        unsigned long       binder_vm_start;
        int                 android_workspace_fd;
        unsigned            android_workspace_size;
        struct task_struct  *task;
        wait_queue_head_t   wait;
        struct list_head    upcalls;
        spinlock_t          lock;
};

struct expressos_venus_proc *expressos_venus_find_proc(pid_t pid);
struct expressos_venus_upcall *expressos_venus_alloc_upcall(int type, unsigned payload_size);
void expressos_venus_free_upcall(struct expressos_venus_upcall *);
/*
 * Enqueue an upcall to a process. It takes the ownership of the
 * upcall. The memory of the upcall will be freed in different
 * context.
 */
int  expressos_venus_upcall(struct expressos_venus_proc *proc,
                            struct expressos_venus_upcall *u);

struct file *expressos_venus_fget(struct expressos_venus_proc *proc, int fd);
struct socket *expressos_venus_get_sock(struct expressos_venus_proc *proc, int fd, int *err);

int expressos_venus_downcall_register_helper(struct expressos_venus_proc *,
                                             const struct expressos_venus_downcall *);
int expressos_venus_downcall_close(struct expressos_venus_proc *,
                                   const struct expressos_venus_downcall *);
int expressos_venus_downcall_pipe(struct expressos_venus_proc *,
                                  const struct expressos_venus_downcall *);
int expressos_venus_downcall_socket(struct expressos_venus_proc *,
                                    const struct expressos_venus_downcall *);
int expressos_venus_downcall_poll(struct expressos_venus_proc *,
                                  const struct expressos_venus_downcall *);
int expressos_venus_downcall_alien_mmap2(struct expressos_venus_proc *,
                                         const struct expressos_venus_downcall *);
int expressos_venus_downcall_futex_wait(struct expressos_venus_proc *,
                                        const struct expressos_venus_downcall *);
int expressos_venus_downcall_futex_wake(struct expressos_venus_proc *,
                                        const struct expressos_venus_downcall *);
int expressos_venus_downcall_binder_write_read(struct expressos_venus_proc *,
                                               const struct expressos_venus_downcall *);

struct expressos_ipc_req {
        struct work_struct work;
        ulong start_time;
        l4_msg_regs_t mr;
        l4_msgtag_t tag;
};

struct expressos_ipc_ret {
        struct list_head list;
        l4_msg_regs_t mr;
        l4_msgtag_t tag;
        l4_umword_t bdr;
};

struct proc_dir_entry;
extern struct proc_dir_entry *expressos_proc_ent;

int  expressos_venus_init(void);
void expressos_venus_destroy(void);
int  expressos_proc_init(void);
void expressos_proc_destroy(void);
int  expressos_ipc_init(void);
void expressos_ipc_destroy(void);
void expressos_ipc_alien_shm_init(void);
void expressos_ipc_alien_shm_destroy(void);

void expressos_ipc_dump_stat(struct seq_file *);
void expressos_handle_ipc(l4_umword_t src, l4_msgtag_t tag);
void expressos_flush_ipc_ret_queue(void);
void expressos_ipc_dispatch(struct expressos_ipc_req *w);

void expressos_ipc_kickstart(void);

void expressos_ipc_take_helper(int *helper_pid, unsigned *vm_start,
                               int *workspace_fd, unsigned *workspace_size);
int  expressos_ipc_clock_gettime(int clk_id);
int  expressos_ipc_open(int helper_pid, int flags, int mode);
void expressos_ipc_close(int helper_pid, int fd);
int  expressos_ipc_vfs_read(int helper_pid, int fd, int count, unsigned *pos);
int  expressos_ipc_vfs_read_async(int helper_pid, void *data, int fd,
                                  int count, unsigned *pos);
int  expressos_ipc_vfs_write_async(int helper_pid, void *data, int fd,
                                   int count, unsigned *pos);
int  expressos_ipc_fstat_combined(int helper_pid, int type,
                                  int fd, unsigned *stat_len);
int  expressos_ipc_stat_combined(int helper_pid, int type, unsigned *stat_len);

int  expressos_ipc_open_and_get_size_async(
        int helper_pid, const void *filename,
        int flags, int mode, unsigned *file_size);
int  expressos_ipc_open_and_read_pages_async(
        int helper_pid, void *data,
        int npages,
        int flags, int mode, unsigned *file_size);

int  expressos_ipc_access_async(int helper_pid,
                                const void *filename, int mode);
int  expressos_ipc_ftruncate(int helper_pid, int fd, int length);
void expressos_ipc_pipe(int helper_pid, int *read_pipe, int *write_pipe);
int  expressos_ipc_mkdir(int helper_pid, int mode);
int  expressos_ipc_unlink(int helper_pid);

int  expressos_ipc_ashmem_ioctl(int helper_pid, int fd, unsigned cmd, int arg0);
int  expressos_ipc_ioctl(int helper_pid, int fd, unsigned cmd, int arg0);
int  expressos_ipc_fcntl64(int helper_pid, int fd, int cmd, int arg0);
int  expressos_ipc_scatter_write_page_async(int helper_pid, int fd,
                                            int page_count, const void *data);
void expressos_ipc_socket_async(int helper_pid, unsigned handle,
                                int domain, int type, int protocol);

int  expressos_ipc_set_sockopt_async(int helper_pid, void *buf, int sockfd,
                                     int level, int optname, int optlen);
int  expressos_ipc_get_sockopt_async(int helper_pid, void *buf, int sockfd,
                                     int level, int optname, int *optlen);
int  expressos_ipc_bind_async(int helper_pid, void *addr,
                              int sockfd, int addrlen);
int  expressos_ipc_connect_async(int helper_pid, void *addr,
                                 int sockfd, int addrlen);
int  expressos_ipc_get_sockname_async(int helper_pid, void *addr,
                                      int sockfd, int *addrlen);
void expressos_ipc_poll_async(int helper_pid, unsigned handle,
                              void *fds, int nfds, int timeout);
int  expressos_ipc_sendto(int helper_pid, int sockfd, int len,
                          int flags, int addrlen);
int  expressos_ipc_recvfrom(int helper_pid, int sockfd, int len,
                            int flags, int *addrlen);
int  expressos_ipc_shutdown(int helper_pid, int sockfd, int how);

void expressos_ipc_futex_wait(int helper_pid, uint handle, int op,
                              long uaddr, int val,
                              uint tv_sec, uint tv_nsec,
                              uint bitset);
void expressos_ipc_futex_wake(int helper_pid, uint handle, int op,
                              long uaddr, uint bitset);

int  expressos_ipc_get_user_page(int helper_pid,
                                 uint fault_type, long uaddr);
void expressos_ipc_alien_mmap2(int helper_pid, long addr,
                               int length, int prot, int flags,
                               int fd, int pgoffset);
void expressos_ipc_free_user_pages(int count);
void expressos_ipc_binder_write_read_async(
        int helper_pid, uint handle, void *buffer,
        uint size, uint bwr_write_size,
        uint patch_table_entries, uint patch_table_offset);
void expressos_ipc_write_app_info(int helper_pid, int length);


int  expressos_fstat_helper(struct file *f, struct kstat *stat);

int  expressos_ipc_valid_ptr(const void *);
int  expressos_ipc_valid_trunk(const void *, int size);
void expressos_ipc_return_1(int opcode, l4_mword_t);
void expressos_ipc_return_2(int opcode, l4_mword_t, l4_mword_t);
void expressos_ipc_return_3(int opcode, l4_mword_t, l4_mword_t, l4_mword_t);
void expressos_ipc_return_4(int opcode, l4_mword_t, l4_mword_t,
                            l4_mword_t, l4_mword_t);
void expressos_ipc_return_6(int opcode, l4_mword_t, l4_mword_t, l4_mword_t,
                            l4_mword_t, l4_mword_t, l4_mword_t);

void  expressos_profiler_init(void);
void  expressos_profiler_enable(int en);
int   expressos_profiler_enabled(void);
ulong expressos_profiler_current_msec(void);
void  expressos_profiler_account_call(unsigned scno, long time);
void  expressos_profiler_dump(struct seq_file *seq);


extern l4re_ds_t expressos_ipc_shm_ds;
extern char *expressos_ipc_shm_buf;
struct expressos_control_block;
extern struct expressos_control_block *expressos_control_block;

extern l4_cap_idx_t expressos_glue_tid, expressos_tid;

#endif
