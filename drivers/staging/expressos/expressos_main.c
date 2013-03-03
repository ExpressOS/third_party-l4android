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

#include <asm/generic/task.h>
#include <asm/l4lxapi/thread.h>

#include <linux/pagemap.h>
#include <linux/module.h>
#include <linux/printk.h>

#include <l4/re/c/util/cap.h>
#include <l4/re/env.h>
#include <l4/log/log.h>
#include <l4/sys/ipc_gate.h>

static L4_CV void server_loop(void *data);
static int server_thread_init(const char *gate_name);
static void server_thread_destroy(void);

static l4lx_thread_t server_thread;
l4_cap_idx_t expressos_glue_tid, expressos_tid;

static int __init kmod_init(void)
{
        int ret = 0;

        expressos_tid = l4re_get_env_cap(EXPRESSOS_GATE);

        if ((ret = expressos_ipc_init())) {
                printk(KERN_INFO "expressos: cannot initialize IPC buffer.\n");
                goto out;
        }

        if ((ret = server_thread_init(EXPRESSOS_GLUE_GATE))) {
                printk(KERN_INFO "expressos: cannot initialize server thread.\n");
                goto out;
        }

        /*
         * Start the server thread.
         */
        l4_ipc_send(expressos_glue_tid, l4_utcb(), (l4_msgtag_t){0},
                    L4_IPC_NEVER);

        expressos_ipc_alien_shm_init();
        expressos_profiler_init();

        if ((ret = expressos_proc_init())) {
                printk(KERN_INFO "expressos: cannot initialize procfs.\n");
                goto out;
        }

        if ((ret = expressos_venus_init())) {
                printk(KERN_INFO "expressos: cannot initialize chardev.\n");
                goto out;
        }

        return 0;
out:
        return ret;
}

static void __exit kmod_exit(void)
{
        server_thread_destroy();
        expressos_venus_destroy();
        expressos_proc_destroy();
        expressos_ipc_alien_shm_destroy();
        expressos_ipc_destroy();
}

static int server_thread_init(const char *gate_name)
{
        l4_cap_idx_t gate;
        l4_msgtag_t tag;
        l4_umword_t label = 0;

	gate = l4re_get_env_cap(gate_name);
        if (l4_is_invalid_cap(gate))
                return -ENOENT;

        tag = l4_ipc_gate_get_infos(gate, &label);
        if (l4_ipc_error(tag, l4_utcb()))
                return -EPERM;

        server_thread = l4lx_thread_create(server_loop, 0,
                                           NULL, NULL, 0,
                                           CONFIG_L4_PRIO_IRQ_BASE,
                                           NULL,
                                           "expressos-glue");

        if (!l4lx_thread_is_valid(server_thread))
                return -EPERM;

        expressos_glue_tid = l4lx_thread_get_cap(server_thread);

        tag = l4_ipc_gate_bind_thread(gate, expressos_glue_tid, label);
        if (l4_ipc_error(tag, l4_utcb())) {
                l4lx_thread_shutdown(server_thread, NULL);
                return -EINVAL;
        }

        return 0;
}

static void server_thread_destroy(void)
{
        l4lx_thread_shutdown(server_thread, NULL);
}

static L4_CV void server_loop(void *data)
{
        int do_wait = 1;
	l4_msgtag_t tag = (l4_msgtag_t){0};
	l4_umword_t src = 0;
        struct thread_info *ti = current_thread_info();
        l4_utcb_t *utcb = l4_utcb();

        /* Stack setup */
        *ti = (struct thread_info) INIT_THREAD_INFO(init_task);

        l4x_stack_setup(ti, utcb, 0);
        barrier();

        ti->task          = l4x_idle_task(0);
        ti->exec_domain   = NULL;
        ti->cpu           = 0;
#ifdef ARCH_x86
        ti->addr_limit    = MAKE_MM_SEG(0);
#endif

        /*
         * Wait until other parts of the system are fully initialized,
         * since some of them requires the tid of the server loop
         * thread.
         */
        l4_ipc_wait(utcb, &src, L4_IPC_NEVER);
        LOG_printf("expressos-venus: server thread started\n");

        for (;;) {
                while (do_wait) {
                        tag = l4_ipc_wait(utcb, &src, L4_IPC_NEVER);
                        do_wait = l4_msgtag_has_error(tag);
                }

                switch (l4_msgtag_label(tag)) {
                        case EXPRESSOS_IPC:
                                expressos_handle_ipc(src, tag);
                                do_wait = 1;
                                continue;

                        case EXPRESSOS_IPC_FLUSH_RET_QUEUE:
                                expressos_flush_ipc_ret_queue();
                                do_wait = 1;
                                continue;

                        default:
                                LOG_printf("expressos-glue: unknown ipc label %ld\n",
                                           l4_msgtag_label(tag));
                                break;
                }

                tag = l4_ipc_reply_and_wait(utcb, tag,
		                            &src, L4_IPC_SEND_TIMEOUT_0);
		do_wait = l4_msgtag_has_error(tag);
        }
}

module_init(kmod_init);
module_exit(kmod_exit);

MODULE_AUTHOR("Haohui Mai <haohui.mai@gmail.com>");
MODULE_DESCRIPTION("ExpressOS Driver");
MODULE_LICENSE("Dual BSD/GPL");
