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
#include <expressos/linux.h>

#include <linux/file.h>
/*

#include <linux/net.h>
#include <linux/un.h>
*/
#include <net/sock.h>

enum {
        OP_BIND,
        OP_CONNECT,
};

static int bind_or_connect_async(int op, int helper_pid, void *addr,
                                 int sockfd, int addrlen);
static ssize_t sendto_helper(struct socket *sock, void *message, size_t length,
                             int flags, struct sockaddr *dest_addr, size_t dest_len);
static ssize_t recvfrom_helper(struct socket *sock, void *buffer,
                               size_t length, int flags,
                               struct sockaddr *address,
                               size_t *address_len);

void expressos_ipc_socket_async(int helper_pid, unsigned handle,
                               int domain, int type, int protocol)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct expressos_venus_upcall *u;

        if (!(proc = expressos_venus_find_proc(helper_pid))) {
                ret = -EINVAL;
                goto err;
        }

        u = expressos_venus_alloc_upcall(EXPRESSOS_VENUS_SOCKET,
                                         sizeof(handle) +
                                         sizeof(struct expressos_venus_socket_in));
        if (!u) {
                ret = -ENOMEM;
                goto err;
        }

        u->async.handle          = handle;
        u->async.socket.domain   = domain;
        u->async.socket.type     = type;
        u->async.socket.protocol = protocol;

        ret = expressos_venus_upcall(proc, u);
        if (ret) {
                expressos_venus_free_upcall(u);
                goto err;
        }

        return;

err:
        expressos_ipc_return_2(expressos_op_socket_async, handle, ret);
        return;
}

int expressos_venus_downcall_socket(struct expressos_venus_proc *proc,
                                    const struct expressos_venus_downcall *d)
{
        expressos_ipc_return_2(expressos_op_socket_async,
                               d->async.handle, d->async.ret);
        return 0;
}

int expressos_ipc_set_sockopt_async(int helper_pid, void *buf, int sockfd,
                                    int level, int optname, int optlen)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct socket *sock;

        if (!expressos_ipc_valid_trunk(buf, optlen))
                return -EFAULT;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(sock = expressos_venus_get_sock(proc, sockfd, &ret)))
                return ret;

        ret = kernel_setsockopt(sock, level, optname, (char*)buf, optlen);
        sockfd_put(sock);
        return ret;
}

int expressos_ipc_get_sockopt_async(int helper_pid, void *buf, int sockfd,
                                    int level, int optname, int *optlen)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct socket *sock;

        if (!expressos_ipc_valid_trunk(buf, *optlen))
                return -EFAULT;

        if (*optlen > EXPRESSOS_IPC_BUF_SIZE)
                return -ENOMEM;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(sock = expressos_venus_get_sock(proc, sockfd, &ret)))
                return ret;

        ret = kernel_getsockopt(sock, level, optname, (char*)buf, optlen);
        sockfd_put(sock);
        return ret;
}

int expressos_ipc_bind_async(int helper_pid, void *addr,
                             int sockfd, int addrlen)
{
        return bind_or_connect_async(OP_BIND, helper_pid, addr,
                                     sockfd, addrlen);
}

int expressos_ipc_connect_async(int helper_pid, void *addr,
                                int sockfd, int addrlen)
{
        return bind_or_connect_async(OP_CONNECT, helper_pid, addr,
                                     sockfd, addrlen);
}

int expressos_ipc_get_sockname_async(int helper_pid, void *addr,
                                     int sockfd, int *addrlen)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct socket *sock;

        if (!expressos_ipc_valid_trunk(addr, *addrlen))
                return -EFAULT;

        if (*addrlen > EXPRESSOS_IPC_BUF_SIZE)
                return -ENOMEM;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(sock = expressos_venus_get_sock(proc, sockfd, &ret)))
                return ret;

        ret = kernel_getsockname(sock, (struct sockaddr*)addr, addrlen);
        sockfd_put(sock);
        return ret;
}

void expressos_ipc_poll_async(int helper_pid, unsigned handle,
                              void *fds, int nfds, int timeout)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct expressos_venus_upcall *u;
        size_t pollfd_size = nfds * sizeof(struct pollfd);

        if (!expressos_ipc_valid_trunk(fds, pollfd_size)) {
                ret = -EFAULT;
                goto err;
        }

        if (!(proc = expressos_venus_find_proc(helper_pid))) {
                ret = -EINVAL;
                goto err;
        }

        u = expressos_venus_alloc_upcall(EXPRESSOS_VENUS_POLL,
                                         sizeof(handle) + pollfd_size +
                                         sizeof(struct expressos_venus_poll_in));
        if (!u) {
                ret = -ENOMEM;
                goto err;
        }

        u->async.handle       = handle;
        u->async.poll.buffer  = (unsigned long)fds;
        u->async.poll.nfds    = nfds;
        u->async.poll.timeout = timeout;
        memcpy(u->async.poll.fds, fds, pollfd_size);

        ret = expressos_venus_upcall(proc, u);
        if (ret) {
                expressos_venus_free_upcall(u);
                goto err;
        }

        return;

err:
        expressos_ipc_return_2(expressos_op_poll_async, handle, ret);
        return;
}

int expressos_venus_downcall_poll(struct expressos_venus_proc *proc,
                                  const struct expressos_venus_downcall *d)

{
        int ret          = d->async.poll.ret;
        int pollfd_size  = ret > 0 ? ret * sizeof(struct pollfd) : 0;
        void *result_ptr = (void*)d->async.poll.buffer;

        if (!expressos_ipc_valid_trunk(result_ptr, pollfd_size))
                ret = -EFAULT;

        if (ret > 0)
                memcpy(result_ptr, d->async.poll.fds, pollfd_size);

        expressos_ipc_return_2(expressos_op_poll_async,
                               d->async.handle, ret);
        return 0;
}


int expressos_ipc_sendto(int helper_pid, int sockfd, int len,
                         int flags, int addrlen)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct socket *sock;

        if (!expressos_ipc_valid_trunk(expressos_ipc_shm_buf, len + addrlen))
                return -EFAULT;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(sock = expressos_venus_get_sock(proc, sockfd, &ret)))
                return ret;

        ret = sendto_helper(sock, expressos_ipc_shm_buf, len, flags,
                            (struct sockaddr*)(expressos_ipc_shm_buf + len),
                            addrlen);
        sockfd_put(sock);
        return ret;
}

int expressos_ipc_recvfrom(int helper_pid, int sockfd, int len,
                           int flags, int *addrlen)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct socket *sock;
        struct sockaddr_storage address;

        if (len + *addrlen > EXPRESSOS_IPC_SYNC_CALL_BUF_SIZE)
                return -ENOMEM;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(sock = expressos_venus_get_sock(proc, sockfd, &ret)))
                return ret;

        ret = recvfrom_helper(sock, expressos_ipc_shm_buf, len, flags,
                              (struct sockaddr*)&address, addrlen);

        if (ret >= 0) {
                if (ret + *addrlen > EXPRESSOS_IPC_SYNC_CALL_BUF_SIZE)
                        return -ENOMEM;

                memcpy(expressos_ipc_shm_buf + ret, &address, *addrlen);
        }

        sockfd_put(sock);
        return ret;
}

int expressos_ipc_shutdown(int helper_pid, int sockfd, int how)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct socket *sock;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(sock = expressos_venus_get_sock(proc, sockfd, &ret)))
                return ret;

        ret = kernel_sock_shutdown(sock, how);
        sockfd_put(sock);
        return ret;
}

static int bind_or_connect_async(int op, int helper_pid, void *addr,
                                 int sockfd, int addrlen)
{
        int ret;
        struct expressos_venus_proc *proc;
        struct socket *sock;

        if (!expressos_ipc_valid_trunk(addr, addrlen))
                return -EFAULT;

        if (!(proc = expressos_venus_find_proc(helper_pid)))
                return -EINVAL;

        if (!(sock = expressos_venus_get_sock(proc, sockfd, &ret)))
                return ret;

        if (op == OP_BIND)
                ret = kernel_bind(sock, (struct sockaddr*)addr, addrlen);
        else
                ret = kernel_connect(sock, (struct sockaddr*)addr,
                                     addrlen, sock->file->f_flags);

        sockfd_put(sock);
        return ret;
}

static ssize_t sendto_helper(struct socket *sock, void *message, size_t length,
                             int flags, struct sockaddr *dest_addr, size_t dest_len)
{
	int err;
	struct msghdr msg;
	struct kvec iov;

	iov.iov_base = message;
	iov.iov_len = length;
	msg.msg_name = NULL;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = 0;

	if (dest_len) {
		msg.msg_name = dest_addr;
		msg.msg_namelen = dest_len;
	}

	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	msg.msg_flags = flags;
	err = kernel_sendmsg(sock, &msg, &iov, 1, length);

	return err;
}

static ssize_t recvfrom_helper(struct socket *sock, void *buffer,
                               size_t length,
                               int flags, struct sockaddr *address,
                               size_t *address_len)
{
        struct kvec iov;
        struct msghdr msg;
        int err;

        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        iov.iov_len = length;
        iov.iov_base = buffer;
        msg.msg_name = address;
        msg.msg_namelen = *address_len;

        if (sock->file->f_flags & O_NONBLOCK)
                flags |= MSG_DONTWAIT;
        err = kernel_recvmsg(sock, &msg, &iov, 1, length, flags);

        return err;
}
