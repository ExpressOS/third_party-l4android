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

#include <linux/highmem.h>
#include <linux/pagemap.h>

struct shared_page_entry {
        struct list_head list;
        struct page      *page;
        ulong            kaddr;
};

static struct shared_pages {
        struct list_head   list;
        struct kmem_cache *cachep;
        spinlock_t         lock;
} shared_pages;

extern void *l4x_main_memory_start;

void expressos_ipc_alien_shm_init(void)
{
        INIT_LIST_HEAD(&shared_pages.list);
        spin_lock_init(&shared_pages.lock);
        shared_pages.cachep = KMEM_CACHE(shared_page_entry,
                                         SLAB_PANIC | SLAB_NOTRACK
                                         | SLAB_RECLAIM_ACCOUNT);
}

void expressos_ipc_alien_shm_destroy(void)
{
        unsigned long flags;
        struct list_head *lh, *q;
        struct shared_page_entry *e;

        spin_lock_irqsave(&shared_pages.lock, flags);
        list_for_each_safe(lh, q, &shared_pages.list) {
                e = list_entry(lh, struct shared_page_entry, list);
                if (!PageReserved(e->page))
                        SetPageDirty(e->page);

                kunmap(e->page);
                release_pages(&e->page, 1, 0);

                list_del(&e->list);
                kmem_cache_free(shared_pages.cachep, e);
        }
        spin_unlock_irqrestore(&shared_pages.lock, flags);

        kmem_cache_destroy(shared_pages.cachep);
}

int expressos_ipc_get_user_page(int helper_pid,
                                uint fault_type, long uaddr)
{
        int ret;
        unsigned long flags;
        struct page *mapped_page;
        struct shared_page_entry *entry;
        struct expressos_venus_proc *proc;

        uaddr = uaddr & ~(PAGE_SIZE - 1);

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        down_read(&proc->task->mm->mmap_sem);
        ret = get_user_pages(NULL, proc->task->mm, uaddr,
                             1, fault_type != 0, 0,
                             &mapped_page, NULL);
        up_read(&proc->task->mm->mmap_sem);

        if (ret != 1)
                return -EFAULT;

        /*
         * Record the entry so that the kernel can reclaim it later.
         */
        entry        = kmem_cache_alloc(shared_pages.cachep, GFP_KERNEL);
        entry->page  = mapped_page;
        entry->kaddr = (ulong)kmap(mapped_page) - (ulong)l4x_main_memory_start;

        spin_lock_irqsave(&shared_pages.lock, flags);
        list_add_tail(&entry->list, &shared_pages.list);
        spin_unlock_irqrestore(&shared_pages.lock, flags);

        return entry->kaddr;
}

void expressos_ipc_alien_mmap2(int helper_pid, long addr,
                               int length, int prot, int flags,
                               int fd, int pgoffset)
{
        int ret;
        struct expressos_venus_upcall *u;
        struct expressos_venus_proc *proc;

        if (!(proc = expressos_venus_find_proc(helper_pid))) {
                ret = -EINVAL;
                goto err;
        }

        u = expressos_venus_alloc_upcall(EXPRESSOS_VENUS_ALIEN_MMAP2,
                                         sizeof(struct expressos_venus_alien_mmap2_in));
        if (!u) {
                ret = -ENOMEM;
                goto err;
        }

        u->mmap2.addr     = addr;
        u->mmap2.length   = length;
        u->mmap2.prot     = prot;
        u->mmap2.flags    = flags;
        u->mmap2.fd       = fd;
        u->mmap2.pgoffset = pgoffset;

        ret = expressos_venus_upcall(proc, u);
        if (ret) {
                expressos_venus_free_upcall(u);
                goto err;
        }

        return;

err:
        expressos_ipc_return_1(expressos_op_alien_mmap2, ret);
        return;
}

int expressos_venus_downcall_alien_mmap2(struct expressos_venus_proc *proc,
                                        const struct expressos_venus_downcall *d)
{
        expressos_ipc_return_1(expressos_op_alien_mmap2, d->ret);
        return 0;
}

void expressos_ipc_free_user_pages(int count)
{
        int i, found, total_pages;
        unsigned long flags;
        unsigned long rel_addr;
        struct list_head *lh, *q;
        struct shared_page_entry *e;

        unsigned long *addrs = (unsigned long *)expressos_ipc_shm_buf;
        struct page **pages = kmalloc(count * sizeof(struct page *), GFP_KERNEL);
        if (!pages)
        {
                printk(KERN_WARNING "expressos_ipc_free_user_pages: "
                       "failed to allocate buffer\n");
                return;
        }

        for (i = 0, total_pages = 0; i < count; ++i) {
                found = 0;
                rel_addr = addrs[i];

                spin_lock_irqsave(&shared_pages.lock, flags);
                list_for_each_safe(lh, q, &shared_pages.list) {
                        e = list_entry(lh, struct shared_page_entry, list);

                        if (e->kaddr == rel_addr) {
                                found = 1;
                                ++total_pages;
                                if (!PageReserved(e->page))
                                        SetPageDirty(e->page);

                                kunmap(e->page);
                                pages[i] = e->page;

                                list_del(&e->list);
                                kmem_cache_free(shared_pages.cachep, e);
                                break;
                        }
                }
                spin_unlock_irqrestore(&shared_pages.lock, flags);

                if (!found) {
                        printk(KERN_WARNING "expressos_ipc_free_user_pages: "
                               "invalid user page 0x%lx\n", addrs[i]);
                }
        }

        release_pages(pages, total_pages, 0);
        kfree(pages);
}
