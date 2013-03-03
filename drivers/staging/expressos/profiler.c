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

#include <linux/time.h>
#include <linux/seq_file.h>

struct profiler_entry {
        ulong start;
        ulong invoke_times;
        ulong total_time;
};

static struct profiler_entry profile[expressos_op_count];
static int profiler_enabled;

static ulong current_msec(void)
{
        struct timespec ts = current_kernel_time();
        return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

ulong expressos_profiler_current_msec(void)
{
        return current_msec();
}

void expressos_profiler_init(void)
{
        memset(profile, 0, sizeof(profile));
        profiler_enabled = 0;
}

void expressos_profiler_enable(int en)
{
        profiler_enabled = !!en;
}

int expressos_profiler_enabled(void)
{
        return profiler_enabled;
}

void expressos_profiler_account_call(unsigned scno, long time)
{
        if (!profiler_enabled || scno >= expressos_op_count)
                return;

        ++profile[scno].invoke_times;
        profile[scno].total_time += time;
}

void expressos_profiler_dump(struct seq_file *seq)
{
        int i = 0;
        for (i = 0; i < sizeof(profile) / sizeof(struct profiler_entry); ++i) {
                struct profiler_entry *e = &profile[i];
                if (!e->invoke_times)
                        continue;

                seq_printf(seq, "%d,%ld,%ld\n", i, e->invoke_times, e->total_time);
        }
}
