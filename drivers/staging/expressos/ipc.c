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
#include "ipc-stubs.h"

#include <expressos/linux.h>

#include <linux/seq_file.h>

#include <l4/log/log.h>

int expressos_ipc_buffer_init(void **ipc_shm_buf, unsigned long buf_size);
int expressos_ipc_buffer_destroy(void);

extern l4re_ds_t l4x_ds_mainmem, expressos_ipc_shm_ds;
extern unsigned long l4x_mainmem_size;

static struct expressos_ipc_return_queue {
        spinlock_t lock;
        size_t count;
        struct list_head list;
        struct expressos_ipc_ret *sync_call_ret;
} ipc_return_queue;

char *expressos_ipc_shm_buf;
struct expressos_control_block *expressos_control_block;

static struct workqueue_struct *ipc_req_work_queue;
static struct kmem_cache *ipc_req_item_cachep, *ipc_ret_item_cachep;
static int ipc_sync_call_id;
static void handle_ipc_request(struct work_struct *);
static void expressos_ipc_queue_ret(struct expressos_ipc_ret *w);
static int flush_ipc_ret_internal(struct expressos_ipc_ret *h, int force);

int expressos_ipc_init(void)
{
        int ret = expressos_ipc_buffer_init((void**)&expressos_ipc_shm_buf,
                                            EXPRESSOS_IPC_BUF_SIZE);
        if (ret)
                return ret;

        expressos_control_block = (struct expressos_control_block*)
                        (expressos_ipc_shm_buf + EXPRESSOS_CONTROL_BLOCK_OFFSET);
        memset(expressos_control_block, 0, EXPRESSOS_CONTROL_BLOCK_SIZE);

        ipc_req_item_cachep = KMEM_CACHE(expressos_ipc_req,
                                      SLAB_PANIC | SLAB_NOTRACK
                                      | SLAB_RECLAIM_ACCOUNT);

        ipc_ret_item_cachep = KMEM_CACHE(expressos_ipc_ret,
                                      SLAB_PANIC | SLAB_NOTRACK
                                      | SLAB_RECLAIM_ACCOUNT);

        ipc_req_work_queue = alloc_workqueue("expressos",
                                     WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND,
                                     WQ_UNBOUND_MAX_ACTIVE);

        spin_lock_init(&ipc_return_queue.lock);
        INIT_LIST_HEAD(&ipc_return_queue.list);
        ipc_return_queue.count = 0;

        return 0;
}

void expressos_ipc_destroy(void)
{
        destroy_workqueue(ipc_req_work_queue);
        kmem_cache_destroy(ipc_ret_item_cachep);
        kmem_cache_destroy(ipc_req_item_cachep);
        expressos_ipc_buffer_destroy();
}

void expressos_ipc_kickstart(void)
{
        struct expressos_ipc_ret u;
        l4_msg_regs_t *mr = &u.mr;

        u.tag = l4_msgtag(EXPRESSOS_IPC, 4, 2, 0);
        u.bdr = 0;

        mr->mr[0] = expressos_op_kickstart;
        mr->mr[1] = EXPRESSOS_IPC_BUF_SIZE;
        mr->mr[2] = EXPRESSOS_CONTROL_BLOCK_OFFSET;
        mr->mr[3] = l4x_mainmem_size;
        mr->mr[4] = L4_ITEM_MAP;
        mr->mr[5] = l4_obj_fpage(expressos_ipc_shm_ds, 0, L4_FPAGE_RWX).raw;
        mr->mr[6] = L4_ITEM_MAP;
        mr->mr[7] = l4_obj_fpage(l4x_ds_mainmem, 0, L4_FPAGE_RWX).raw;

        flush_ipc_ret_internal(&u, true);
}

void expressos_ipc_dump_stat(struct seq_file *seq)
{
        seq_printf(seq,
                   "active_sync_call: %d\n"
                   "ipc_ret_queue_count: %d\n"
                   "pending_reply_count: %d\n",
                   ipc_sync_call_id,
                   ipc_return_queue.count,
                   expressos_control_block->pending_reply_count);
}

static void copy_ipc_data(l4_msg_regs_t *dst, const l4_msg_regs_t *src, l4_msgtag_t tag)
{
        size_t copy_item_num = l4_msgtag_words(tag) + l4_msgtag_items(tag) * 2;
        BUG_ON(copy_item_num > L4_UTCB_GENERIC_DATA_SIZE);

        memcpy(dst, src, copy_item_num * sizeof(l4_umword_t));
}

void expressos_handle_ipc(l4_umword_t src, l4_msgtag_t tag)
{
        /*
         * Make a copy of the message registers as soon as possible,
         * because many functions in the kernel, including printk()
         * and vmalloc() will change the message registers.
         */
        struct expressos_ipc_req *w = kmem_cache_alloc(ipc_req_item_cachep, GFP_KERNEL);
        int opcode;

        copy_ipc_data(&w->mr, l4_utcb_mr(), tag);
        w->tag = tag;

        opcode = w->mr.mr[0];
        if (!expressos_ipc_is_async_call(opcode))
                ipc_sync_call_id = opcode;

        INIT_WORK(&w->work, handle_ipc_request);
        queue_work(ipc_req_work_queue, &w->work);
}

static void handle_ipc_request(struct work_struct *w)
{
        expressos_ipc_dispatch((struct expressos_ipc_req *)w);
        kmem_cache_free(ipc_req_item_cachep, w);
}

static int flush_ipc_ret_internal(struct expressos_ipc_ret *h, int force)
{
        l4_msgtag_t res;
        l4_utcb_t *utcb   = l4_utcb();
        l4_msg_regs_t *mr = l4_utcb_mr_u(utcb);

        copy_ipc_data(mr, &h->mr, h->tag);
        if (l4_msgtag_items(h->tag))
                l4_utcb_br_u(utcb)->bdr = h->bdr;

        res = l4_ipc_send(expressos_tid, utcb, h->tag,
                          force ? L4_IPC_NEVER : L4_IPC_SEND_TIMEOUT_0);

        return l4_ipc_error(res, utcb);
}

void expressos_flush_ipc_ret_queue(void)
{
        unsigned long flags;
        struct list_head *lh, *tmp;
        struct expressos_ipc_ret *h;
        struct expressos_ipc_return_queue *q = &ipc_return_queue;

        spin_lock_irqsave(&q->lock, flags);

        if (q->sync_call_ret) {
                h = q->sync_call_ret;
                q->sync_call_ret = NULL;
                ipc_sync_call_id = 0;

                if (flush_ipc_ret_internal(h, false))
                        LOG_printf("Reply to sync call %d failed\n",
                                   ipc_sync_call_id);

                --q->count;
                --expressos_control_block->pending_reply_count;
                kmem_cache_free(ipc_ret_item_cachep, h);
        }

        if (!ipc_sync_call_id) {
                list_for_each_safe(lh, tmp, &q->list) {
                        h = list_entry(lh, struct expressos_ipc_ret, list);
                        if (flush_ipc_ret_internal(h, false))
                                break;

                        --q->count;
                        --expressos_control_block->pending_reply_count;
                        list_del(lh);
                        kmem_cache_free(ipc_ret_item_cachep, h);
                }
        }

        spin_unlock_irqrestore(&q->lock, flags);
        return;
}

static void expressos_ipc_queue_ret(struct expressos_ipc_ret *w)
{
        unsigned long flags;
        l4_msgtag_t tag;
        int opcode = w->mr.mr[0];

        spin_lock_irqsave(&ipc_return_queue.lock, flags);

        if (expressos_ipc_is_async_call(opcode)) {
                list_add_tail(&(w->list), &ipc_return_queue.list);
        } else {
                BUG_ON(ipc_return_queue.sync_call_ret);
                ipc_return_queue.sync_call_ret = w;
        }

        ++ipc_return_queue.count;
        ++expressos_control_block->pending_reply_count;
        spin_unlock_irqrestore(&ipc_return_queue.lock, flags);

        tag = l4_msgtag(EXPRESSOS_IPC_FLUSH_RET_QUEUE, 0, 0, 0);
        l4_ipc_send(expressos_glue_tid, l4_utcb(), tag, L4_IPC_NEVER);
}

void expressos_ipc_return_1(int opcode, l4_mword_t v1)
{
        struct expressos_ipc_ret *w = kmem_cache_alloc(ipc_ret_item_cachep,
                                                       GFP_KERNEL);
        l4_msg_regs_t *mr = &w->mr;
        w->tag = l4_msgtag(EXPRESSOS_IPC, 2, 0, 0);

        mr->mr[0] = opcode;
        mr->mr[1] = v1;

        expressos_ipc_queue_ret(w);
}

void expressos_ipc_return_2(int opcode, l4_mword_t v1, l4_mword_t v2)
{
        struct expressos_ipc_ret *w = kmem_cache_alloc(ipc_ret_item_cachep,
                                                       GFP_KERNEL);
        l4_msg_regs_t *mr = &w->mr;
        w->tag = l4_msgtag(EXPRESSOS_IPC, 3, 0, 0);

        mr->mr[0] = opcode;
        mr->mr[1] = v1;
        mr->mr[2] = v2;

        expressos_ipc_queue_ret(w);
}

void expressos_ipc_return_3(int opcode, l4_mword_t v1, l4_mword_t v2,
                            l4_mword_t v3)
{
        struct expressos_ipc_ret *w = kmem_cache_alloc(ipc_ret_item_cachep,
                                                       GFP_KERNEL);
        l4_msg_regs_t *mr = &w->mr;
        w->tag = l4_msgtag(EXPRESSOS_IPC, 4, 0, 0);

        mr->mr[0] = opcode;
        mr->mr[1] = v1;
        mr->mr[2] = v2;
        mr->mr[3] = v3;

        expressos_ipc_queue_ret(w);
}

void expressos_ipc_return_4(int opcode, l4_mword_t v1, l4_mword_t v2,
                            l4_mword_t v3, l4_mword_t v4)
{
        struct expressos_ipc_ret *w = kmem_cache_alloc(ipc_ret_item_cachep,
                                                       GFP_KERNEL);
        l4_msg_regs_t *mr = &w->mr;
        w->tag = l4_msgtag(EXPRESSOS_IPC, 5, 0, 0);

        mr->mr[0] = opcode;
        mr->mr[1] = v1;
        mr->mr[2] = v2;
        mr->mr[3] = v3;
        mr->mr[4] = v4;

        expressos_ipc_queue_ret(w);
}

void expressos_ipc_return_6(int opcode, l4_mword_t v1, l4_mword_t v2, l4_mword_t v3,
                            l4_mword_t v4, l4_mword_t v5, l4_mword_t v6)
{
        struct expressos_ipc_ret *w = kmem_cache_alloc(ipc_ret_item_cachep,
                                                       GFP_KERNEL);
        l4_msg_regs_t *mr = &w->mr;
        w->tag = l4_msgtag(EXPRESSOS_IPC, 7, 0, 0);

        mr->mr[0] = opcode;
        mr->mr[1] = v1;
        mr->mr[2] = v2;
        mr->mr[3] = v3;
        mr->mr[4] = v4;
        mr->mr[5] = v5;
        mr->mr[6] = v6;

        expressos_ipc_queue_ret(w);
}

int expressos_ipc_valid_ptr(const void *ptr)
{
        const char *p = (const char *)ptr;
        return p >= expressos_ipc_shm_buf
                        && p < expressos_ipc_shm_buf + EXPRESSOS_IPC_BUF_SIZE;
}

int  expressos_ipc_valid_trunk(const void *ptr, int size)
{
        const char *p = (const char *)ptr;
        return size >= 0 && expressos_ipc_valid_ptr(p)
                        && expressos_ipc_valid_ptr(p + size);
}
