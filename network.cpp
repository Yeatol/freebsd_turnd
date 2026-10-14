/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Yeatol <vim@vimer.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "network.h"

#include <span>
#include <array>
#include <vector>
#include <thread>
#include <stdint.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/cpuset.h>
#include <sys/socket.h>
#include <netinet/in.h>

static thread_local struct network_tls_t
{
    std::vector<mmsghdr>                   udp_msgs;
    std::vector<iovec>                     udp_iovs;
    std::vector<sockaddr_in6>              udp_addrs;
    std::vector<std::array<uint8_t, 1232>> udp_buffers;
} tls;

static int network_socket_udp(uint16_t port)
{
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);

    if (fd == -1) return -1;

    int ipv6only  = 0;
    int reuseaddr = 1;
    int reuseport = 1;

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,     &ipv6only,  sizeof(int)) == -1) { close(fd); return -1; }
    if (setsockopt(fd, SOL_SOCKET,   SO_REUSEADDR,    &reuseaddr, sizeof(int)) == -1) { close(fd); return -1; }
    if (setsockopt(fd, SOL_SOCKET,   SO_REUSEPORT_LB, &reuseport, sizeof(int)) == -1) { close(fd); return -1; }

    sockaddr_in6 address = {};
    address.sin6_family  = AF_INET6;
    address.sin6_port    = htons(port);
    address.sin6_addr    = in6addr_any;

    if (bind(fd, (sockaddr*)&address, sizeof(address)) == -1) { close(fd); return -1; }

    return fd;
}

static void network_udp_event_handler(const struct kevent& e)
{
    int recv_size = recvmmsg(e.ident, tls.udp_msgs.data(), tls.udp_msgs.size(), 0, 0);

    if (recv_size <= 0) return;

    uint32_t offset = 0;
    uint32_t count  = 0;

    for (int i = 0; i < recv_size; ++i)
    {
        bool drop = true;
        uint32_t data_size = tls.udp_msgs[i].msg_len;
        network_udp_handler(tls.udp_addrs[i].sin6_addr.s6_addr, tls.udp_addrs[i].sin6_port, tls.udp_buffers[i], data_size, drop);
        tls.udp_iovs[i].iov_len = data_size;

        if (drop)
        {
            if (count > 0) sendmmsg(e.ident, tls.udp_msgs.data() + offset, count, 0);
            offset = offset + count + 1;
            count = 0;
            continue;
        }

        count += 1;
    }

    if (count > 0) sendmmsg(e.ident, tls.udp_msgs.data() + offset, count, 0);

    for (int i = 0; i < recv_size; ++i)
    {
        tls.udp_iovs[i].iov_len = tls.udp_buffers[i].size();
        tls.udp_msgs[i].msg_hdr.msg_namelen = sizeof(tls.udp_addrs[i]);
    }
}

static void network_thread(int cpu_id, uint16_t port)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu_id, &mask);
    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(mask), &mask) != 0) _exit(-1);

    struct kevent event = {};
    int kqueue_id  = kqueue1(O_CLOEXEC);
    int socket_udp = network_socket_udp(port);
    EV_SET(&event, socket_udp, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(kqueue_id, &event, 1, 0, 0, 0) == -1) _exit(-1);

    if (tls.udp_msgs.empty())
    {
        tls.udp_msgs.resize(1024);
        tls.udp_iovs.resize(tls.udp_msgs.size());
        tls.udp_addrs.resize(tls.udp_msgs.size());
        tls.udp_buffers.resize(tls.udp_msgs.size());
        for (int i = 0; i < tls.udp_msgs.size(); ++i)
        {
            tls.udp_iovs[i].iov_base            = tls.udp_buffers[i].data();
            tls.udp_iovs[i].iov_len             = tls.udp_buffers[i].size();
            tls.udp_msgs[i].msg_hdr.msg_name    = &tls.udp_addrs[i];
            tls.udp_msgs[i].msg_hdr.msg_namelen = sizeof(tls.udp_addrs[i]);
            tls.udp_msgs[i].msg_hdr.msg_iov     = &tls.udp_iovs[i];
            tls.udp_msgs[i].msg_hdr.msg_iovlen  = 1;
        }
    }

    std::vector<struct kevent> events(1024);

    while (true)
    {
        int size = kevent(kqueue_id, 0, 0, events.data(), events.size(), 0);
        for (int i = 0; i < size; ++i)
        {
            network_udp_event_handler(events[i]);
        }
    }
}

void network_server(uint16_t port)
{
    size_t cpu_count = std::thread::hardware_concurrency();
    for (int cpu_id = 0; cpu_id < cpu_count; ++cpu_id)
    {
        std::thread(network_thread, cpu_id, port).detach();
    }
}

__attribute__((weak)) void network_udp_handler(std::span<uint8_t, 16> ip, uint16_t& port, std::span<uint8_t, 1232> buffer, uint32_t& size, bool& drop)
{
}
