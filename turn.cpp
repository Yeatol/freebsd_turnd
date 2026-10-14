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

#include "turn.h"

#include <bit>
#include <span>
#include <cstring>
#include <concepts>
#include <stdint.h>

#pragma pack(push, 1)

struct message_header_t
{
    uint16_t type;
    uint16_t length;
    uint32_t magic_cookie;
    uint8_t  transaction_id[12];
    uint16_t turn_type;
    uint16_t x_peer_port;
    uint8_t  x_peer_address[16];
};

#pragma pack(pop)

namespace { template <std::integral T> constexpr T hton(T v) { if constexpr (std::endian::native == std::endian::little) return std::byteswap(v); else return v; } }

static bool is_peer_address_allowed(std::span<uint8_t, 16> ip, uint16_t port)
{
    if (port < 1024) return false;

    constexpr uint8_t ipv4_mapped[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF};
    if (std::memcmp(ip.data(), ipv4_mapped, 12) == 0)
    {
        uint32_t ipv4 = hton<uint32_t>(*(uint32_t*)(ip.data() + 12));

        // 127.0.0.0/8 (Loopback)
        if ((ipv4 & 0xFF000000) == 0x7F000000) return false;
        // 10.0.0.0/8 (Private)
        if ((ipv4 & 0xFF000000) == 0x0A000000) return false;
        // 172.16.0.0/12 (Private)
        if ((ipv4 & 0xFFF00000) == 0xAC100000) return false;
        // 192.168.0.0/16 (Private)
        if ((ipv4 & 0xFFFF0000) == 0xC0A80000) return false;
        // 169.254.0.0/16 (Link-Local / Metadata)
        if ((ipv4 & 0xFFFF0000) == 0xA9FE0000) return false;
        // 0.0.0.0/8 (This network)
        if ((ipv4 & 0xFF000000) == 0x00000000) return false;
        // 224.0.0.0/4 (Multicast)
        if ((ipv4 & 0xF0000000) == 0xE0000000) return false;
        // Limited Broadcast
        if (ipv4 == 0xFFFFFFFF) return false;

        return true;
    }

    // ::1
    constexpr uint8_t ipv6_loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (std::memcmp(ip.data(), ipv6_loopback, 16) == 0) return false;

    // ::
    if (ip[0] == 0 && ip[1] == 0 && ip[14] == 0 && ip[15] == 0)
    {
        bool all_zero = true;
        for (int i = 2; i < 14; ++i) { if (ip[i] != 0) { all_zero = false; break; } }
        if (all_zero) return false;
    }

    // fc00::/7
    if ((ip[0] & 0xFE) == 0xFC) return false;

    // fe80::/10
    if (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80) return false;

    // ff00::/8
    if (ip[0] == 0xFF) return false;

    return true;
}

void network_turn_handler(std::span<uint8_t, 16> ip, uint16_t& port, std::span<uint8_t, 1232> buffer, uint32_t& size, bool& drop)
{
    message_header_t* message_header = (message_header_t*)buffer.data();

    if (size < sizeof(message_header_t) || message_header->magic_cookie != hton<uint32_t>(0x12131017)) return;

    uint8_t* magic_cookie = (uint8_t*)&message_header->magic_cookie;

    if (message_header->turn_type == hton<uint16_t>(0x0001))
    {
        message_header->turn_type = hton<uint16_t>(0x0101);

        message_header->x_peer_port = port ^ hton<uint16_t>(0x1213);

        for (int i = 0; i < 4; ++i)  message_header->x_peer_address[i] = ip[i] ^ magic_cookie[i];

        for (int i = 4; i < 16; ++i) message_header->x_peer_address[i] = ip[i] ^ message_header->transaction_id[i - 4];

        drop = false;
    }

    if (message_header->turn_type == hton<uint16_t>(0x0002))
    {
        uint8_t  peer_address[16];

        uint16_t peer_port = message_header->x_peer_port ^ hton<uint16_t>(0x1213);

        for (int i = 0; i < 4; ++i)  peer_address[i] = message_header->x_peer_address[i] ^ magic_cookie[i];

        for (int i = 4; i < 16; ++i) peer_address[i] = message_header->x_peer_address[i] ^ message_header->transaction_id[i - 4];

        message_header->turn_type = hton<uint16_t>(0x0102);

        message_header->x_peer_port = port ^ hton<uint16_t>(0x1213);

        for (int i = 0; i < 4; ++i)  message_header->x_peer_address[i] = ip[i] ^ magic_cookie[i];

        for (int i = 4; i < 16; ++i) message_header->x_peer_address[i] = ip[i] ^ message_header->transaction_id[i - 4];

        port = peer_port;

        std::memcpy(ip.data(), peer_address, 16);

        drop = is_peer_address_allowed(ip, port) ? false : true;
    }
}
