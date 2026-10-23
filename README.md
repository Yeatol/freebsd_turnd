# turnd

Minimal NAT traversal and UDP relay server for FreeBSD,
built with a custom protocol inspired by STUN (RFC 8489) / TURN (RFC 8656) standards.

## Summary

`turnd` is a lightweight UDP server for FreeBSD that provides basic NAT traversal
and peer-to-peer datagram relaying. It uses a compact custom protocol inspired
by STUN and TURN: clients can obtain their observed IP address and port, and
the server can forward UDP packets to a peer. The server listens on UDP port
`1213` and supports IPv4 and IPv6.

## Protocol

The server uses a custom binary protocol over UDP; it is inspired by
STUN (RFC 8489) / TURN (RFC 8656) but is not compatible with either standard.
Each datagram starts with a 40-byte header. Multi-byte integer fields are in network byte order.

| Offset | Size | Field | Description |
| ---: | ---: | --- | --- |
| 0 | 2 | `type` | Message type, for application use; turnd passes it through transparently. |
| 2 | 2 | `length` | Payload length, excluding the 40-byte header, for application use; turnd passes it through transparently. |
| 4 | 4 | `magic_cookie` | Must be `0x12131017` in network byte order; turnd silently drops non-compliant packets. |
| 8 | 12 | `transaction_id` | Same as in STUN (RFC 8489); turnd passes it through transparently. |
| 20 | 2 | `turn_type` | `0x0001` performs a STUN (RFC 8489)-like Binding request and turnd modifies it to `0x0101`, `0x0002` performs a TURN (RFC 8656)-like SEND and turnd modifies it to `0x0102`; turnd silently drops non-compliant packets.|
| 22 | 2 | `x_peer_port` | turnd modifies this field to contain the requester's observed port in responses and relay packets. |
| 24 | 16 | `x_peer_address` | turnd modifies this field to contain the requester's observed address in responses and relay packets. |

The XOR encoding follows the same masking method used for XOR-MAPPED-ADDRESS
in STUN (RFC 8489): encode the port by XORing its two network-byte-order bytes
with the most significant 16 bits of `magic_cookie` (`12 13`), and encode the
16-byte address by XORing it with the 16-byte concatenation of
`magic_cookie` and `transaction_id`. Decoding uses the same XOR operation.

## Features

- IPv4 and IPv6 address handling
- No third-party libraries; relies on the FreeBSD base system, C++ standard
  library, and pthread support
- FreeBSD rc.d startup script support
- Multi-threaded UDP server using FreeBSD `kqueue(2)`
- Starts one worker thread per CPU reported by `std::thread::hardware_concurrency()`
  and pins each thread to its corresponding CPU with `cpuset(2)`.
- **Zero dynamic memory allocation at runtime** (pre-allocated thread-local buffers and message rings)
- In-place response generation: rewrites each request in its receive buffer and sends it as the response

## Requirements

- FreeBSD 14 or later
- C++23-capable compiler and FreeBSD `make`

## Building

From the project root:

```sh
make
```

This produces the `turnd` binary in the current working directory.

## Running

Start the server directly:

```sh
./turnd
```

The server listens on UDP port `1213`. It runs in the foreground and
exits when it receives `SIGINT` or `SIGTERM`.

## Installation

Install into the system using the standard FreeBSD `make install` flow:

```sh
make install
```

This installs the `turnd` executable to `/usr/local/sbin/turnd` and the
`turnd` rc.d service script to `/usr/local/etc/rc.d/turnd`.

## rc.d service integration

The `turnd.in` template is processed during the build to generate the rc.d
service script, which is installed as part of `make install`. The generated
script uses FreeBSD's `daemon(8)` utility to run and manage `turnd` as a service.
The service runs the `turnd` process as the `nobody` user.
Manage it using standard FreeBSD service controls such as:

```sh
service turnd start
service turnd status
service turnd stop
```

To enable the service:

```sh
sysrc turnd_enable="YES"
```

To disable the service:

```sh
sysrc -x turnd_enable
```

## License

This project is licensed under the BSD 2-Clause "Simplified" License. See the
`LICENSE` file for full terms and conditions.
