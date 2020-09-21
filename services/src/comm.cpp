/* -*- mode: C++; indent-tabs-mode: nil; c-basic-offset: 4; fill-column: 99; -*-
 */
/* vim: set ts=4 sw=4 et tw=99:  */
/*
    This file is part of Icecream.

    Copyright (c) 2004 Michael Matz <matz@suse.de>
                  2004 Stephan Kulow <coolo@suse.de>
                  2007 Dirk Mueller <dmueller@suse.de>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "comm.hh"

#include "getifaddrs.hh"
#include "logging.hh"
#include "services_job.hh"
#include "type_id.hh"

extern "C" {
#include <arpa/inet.h>
#include <poll.h>
#include <sys/un.h>
#ifdef HAVE_NETINET_TCP_VAR_H
#include <netinet/tcp_var.h>
#include <sys/socketvar.h>
#endif
#include <fcntl.h>
#include <lzo/lzo1x.h>
#include <netdb.h>
#include <zstd.h>
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
}

#include <algorithm>
#include <functional>
#include <unordered_map>
#include <vector>

// Prefer least amount of CPU use
#undef ZSTD_CLEVEL_DEFAULT
#define ZSTD_CLEVEL_DEFAULT 1

// old libzstd?
#ifndef ZSTD_COMPRESSBOUND
#define ZSTD_COMPRESSBOUND(n) ZSTD_compressBound(n)
#endif

/*
 * A generic DoS protection. The biggest messages are of type FileChunk
 * which shouldn't be larger than 100kb. so anything bigger than 10 times
 * of that is definitely fishy, and we must reject it (we're running as root,
 * so be cautious).
 */

#define MAX_MSG_SIZE 1 * 1024 * 1024

/*
 * On a slow and congested network it's possible for a send call to get starved.
 * This will happen especially when trying to send a huge number of bytes over
 * at once. We can avoid this situation to a large extend by sending smaller
 * chunks of data over.
 */
#define MAX_SLOW_WRITE_SIZE 10 * 1024

namespace {

int
zstd_compression()
{
    const char * level = getenv("ICECC_COMPRESSION");
    if (!level || !*level)
        return ZSTD_CLEVEL_DEFAULT;

    char * endptr;
    int    n = strtol(level, &endptr, 0);
    if (*endptr)
        return ZSTD_CLEVEL_DEFAULT;
    return n;
}

std::string
shorten_filename(const std::string & str)
{
    std::string::size_type ofs = str.rfind('/');

    for (int i = 2; i--;) {
        if (ofs != std::string::npos) {
            ofs = str.rfind('/', ofs - 1);
        }
    }

    return str.substr(ofs + 1);
}

size_t
get_max_write_size()
{
    if (const char * icecc_slow_network = getenv("ICECC_SLOW_NETWORK"))
        if (icecc_slow_network[0] == '1')
            return MAX_SLOW_WRITE_SIZE;
    return MAX_MSG_SIZE;
}

int
prepare_connect(const std::string &  hostname,
                unsigned short       p,
                struct sockaddr_in & remote_addr)
{
    int remote_fd;
    int i = 1;

    if ((remote_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        log_perror("socket()");
        return -1;
    }

    struct hostent * host = gethostbyname(hostname.c_str());

    if (!host) {
        log_error() << "Connecting to " << hostname
                    << " failed: " << hstrerror(h_errno) << std::endl;
        if ((-1 == close(remote_fd)) && (errno != EBADF)) {
            log_perror("close failed");
        }
        return -1;
    }

    if (host->h_length != 4) {
        log_error() << "Invalid address length" << std::endl;
        if ((-1 == close(remote_fd)) && (errno != EBADF)) {
            log_perror("close failed");
        }
        return -1;
    }

    setsockopt(remote_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&i, sizeof(i));

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(p);
    std::memcpy(
        &remote_addr.sin_addr.s_addr, host->h_addr_list[0], host->h_length);

    return remote_fd;
}

bool
connect_async(int               remote_fd,
              struct sockaddr * remote_addr,
              size_t            remote_size,
              int               timeout)
{
    fcntl(remote_fd, F_SETFL, O_NONBLOCK);

    // code majorly derived from lynx's http connect (GPL)
    int status = connect(remote_fd, remote_addr, remote_size);

    if ((status < 0) && (errno == EINPROGRESS || errno == EAGAIN)) {
        pollfd pfd;
        pfd.fd = remote_fd;
        pfd.events = POLLOUT;
        int ret;

        do {
            /* we poll for a specific time and if that succeeds, we connect one
               final time. Everything else we ignore */
            ret = poll(&pfd, 1, timeout * 1000);

            if (ret < 0 && errno == EINTR) {
                continue;
            }

            break;
        } while (1);

        if (ret > 0) {
            /*
            **  Extra check here for connection success, if we try to
            **  connect again, and get EISCONN, it means we have a
            **  successful connection.  But don't check with SOCKS.
            */
            status = connect(remote_fd, remote_addr, remote_size);

            if ((status < 0) && (errno == EISCONN)) {
                status = 0;
            }
        }
    }

    if (status < 0) {
        /*
        **  The connect attempt failed or was interrupted,
        **  so close up the socket.
        */
        if ((-1 == close(remote_fd)) && (errno != EBADF)) {
            log_perror("close failed");
        }
        return false;
    } else {
        /*
        **  Make the socket blocking again on good connect.
        */
        fcntl(remote_fd, F_SETFL, 0);
    }

    return true;
}

int
get_second_port_for_debug(int port)
{
    // When running tests, we want to check also interactions between 2
    // schedulers, but when they are both local, they cannot bind to the same
    // port. So make sure to send all broadcasts to both.
    static bool checkedDebug = false;
    static int  debugPort1 = 0;
    static int  debugPort2 = 0;
    if (!checkedDebug) {
        checkedDebug = true;
        if (const char * env = getenv("ICECC_TEST_SCHEDULER_PORTS")) {
            debugPort1 = atoi(env);
            const char * env2 = strchr(env, ':');
            if (env2 != nullptr)
                debugPort2 = atoi(env2 + 1);
        }
    }
    int secondPort = 0;
    if (port == debugPort1)
        secondPort = debugPort2;
    else if (port == debugPort2)
        secondPort = debugPort1;
    return secondPort ? secondPort : -1;
}

/* Returns a filedesc. or a negative value for errors.  */
int
open_send_broadcast(int port, const char * buf, int size)
{
    int                ask_fd;
    struct sockaddr_in remote_addr;

    if ((ask_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        log_perror("open_send_broadcast socket");
        return -1;
    }

    if (fcntl(ask_fd, F_SETFD, FD_CLOEXEC) < 0) {
        log_perror("open_send_broadcast fcntl");
        if (-1 == close(ask_fd)) {
            log_perror("close failed");
        }
        return -1;
    }

    int optval = 1;

    if (setsockopt(ask_fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) <
        0) {
        log_perror("open_send_broadcast setsockopt");
        if (-1 == close(ask_fd)) {
            log_perror("close failed");
        }
        return -1;
    }

    struct kde_ifaddrs * addrs;

    int ret = kde_getifaddrs(&addrs);

    if (ret < 0) {
        return ret;
    }

    for (struct kde_ifaddrs * addr = addrs; addr != nullptr;
         addr = addr->ifa_next) {
        /*
         * See if this interface address is IPv4...
         */

        if (addr->ifa_addr == nullptr || addr->ifa_addr->sa_family != AF_INET ||
            addr->ifa_netmask == nullptr || addr->ifa_name == nullptr) {
            continue;
        }

        static bool in_tests = getenv("ICECC_TESTS") != nullptr;
        if (!in_tests) {
            if (ntohl(
                    ((struct sockaddr_in *)addr->ifa_addr)->sin_addr.s_addr) ==
                0x7f000001) {
                trace() << "ignoring localhost " << addr->ifa_name
                        << " for broadcast" << std::endl;
                continue;
            }

            if ((addr->ifa_flags & IFF_POINTOPOINT) ||
                !(addr->ifa_flags & IFF_BROADCAST)) {
                log_info() << "ignoring tunnels " << addr->ifa_name
                           << " for broadcast" << std::endl;
                continue;
            }
        } else {
            if (ntohl(
                    ((struct sockaddr_in *)addr->ifa_addr)->sin_addr.s_addr) !=
                0x7f000001) {
                trace() << "ignoring non-localhost " << addr->ifa_name
                        << " for broadcast" << std::endl;
                continue;
            }
        }

        if (addr->ifa_broadaddr) {
            log_info() << "broadcast " << addr->ifa_name << " "
                       << inet_ntoa(
                              ((sockaddr_in *)addr->ifa_broadaddr)->sin_addr)
                       << std::endl;

            remote_addr.sin_family = AF_INET;
            remote_addr.sin_port = htons(port);
            remote_addr.sin_addr =
                ((sockaddr_in *)addr->ifa_broadaddr)->sin_addr;

            if (sendto(ask_fd,
                       buf,
                       size,
                       0,
                       (struct sockaddr *)&remote_addr,
                       sizeof(remote_addr)) != size) {
                log_perror("open_send_broadcast sendto");
            }
        }
    }

    kde_freeifaddrs(addrs);
    return ask_fd;
}

} // namespace

/* TODO
 * buffered in/output per MsgChannel
    + move read* into MsgChannel, create buffer-fill function
    + add timeouting poll() there, handle it in the different
    + read* functions.
    + write* unbuffered / or per message buffer (flush in sendMsg)
 * think about error handling
    + saving errno somewhere (in MsgChannel class)
 * handle unknown messages (implement a UnknownMsg holding the content
    of the whole data packet?)
 */

/* Tries to fill the inbuf completely.  */
bool
MsgChannel::readSome()
{
    chopInput();
    size_t count = inbuflen - inofs;

    if (count < 128) {
        inbuflen = (inbuflen + 128 + 127) & ~(size_t)127;
        inbuf = (char *)realloc(inbuf, inbuflen);
        assert(inbuf); // Probably unrecoverable if realloc fails anyway.
        count = inbuflen - inofs;
    }

    char * buf = inbuf + inofs;
    bool   error = false;

    while (count) {
        if (eof_) {
            break;
        }

        ssize_t ret = read(fd, buf, count);

        if (ret > 0) {
            count -= ret;
            buf += ret;
        } else if (ret < 0 && errno == EINTR) {
            continue;
        } else if (ret < 0) {
            // EOF or some error
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                error = true;
            }
        } else if (ret == 0) {
            eof_ = true;
        }

        break;
    }

    inofs = buf - inbuf;

    if (!updateState()) {
        error = true;
    }

    if (error) {
        // Daemons sometimes successfully do accept() but then the connection
        // gets ECONNRESET. Probably a spurious result from accept(), so
        // just be silent about it in this case.
        setError(instate == NEED_PROTO);
        return false;
    }
    return true;
}

bool
MsgChannel::updateState()
{
    switch (instate) {
        case NEED_PROTO:

            while (inofs - intogo >= 4) {
                if (protocol == 0) {
                    return false;
                }

                uint32_t      remote_prot = 0;
                unsigned char vers[4];
                // readuint32 (remote_prot);
                std::memcpy(vers, inbuf + intogo, 4);
                intogo += 4;

                for (int i = 0; i < 4; ++i) {
                    remote_prot |= vers[i] << (i * 8);
                }

                if (protocol == -1) {
                    /* The first time we read the remote protocol.  */
                    protocol = 0;

                    if (remote_prot < MIN_PROTOCOL_VERSION ||
                        remote_prot > (1 << 20)) {
                        remote_prot = 0;
                        setError();
                        return false;
                    }

                    maximum_remote_protocol = remote_prot;

                    if (remote_prot > PROTOCOL_VERSION) {
                        remote_prot = PROTOCOL_VERSION; // ours is smaller
                    }

                    for (int i = 0; i < 4; ++i) {
                        vers[i] = remote_prot >> (i * 8);
                    }

                    writeFull(vers, 4);

                    if (!flushWritebuf(true)) {
                        setError();
                        return false;
                    }

                    protocol = -1 - remote_prot;
                } else if (protocol < -1) {
                    /* The second time we read the remote protocol.  */
                    protocol = -(protocol + 1);

                    if ((int)remote_prot != protocol) {
                        protocol = 0;
                        setError();
                        return false;
                    }

                    instate = NEED_LEN;
                    /* Don't consume bytes from messages.  */
                    break;
                } else {
                    trace() << "NEED_PROTO but protocol > 0" << std::endl;
                    setError();
                    return false;
                }
            }

            /* FALLTHROUGH if the protocol setup was complete (instate was
            changed to NEED_LEN then).  */
            if (instate != NEED_LEN) {
                break;
            }
            // fallthrough
        case NEED_LEN:

            if (inofs - intogo >= 4) {
                (*this) >> inmsglen;

                if (inmsglen > MAX_MSG_SIZE) {
                    log_error() << "received a too large message (size "
                                << inmsglen << "), ignoring" << std::endl;
                    setError();
                    return false;
                }

                if (inbuflen - intogo < inmsglen) {
                    inbuflen = (inmsglen + intogo + 127) & ~(size_t)127;
                    inbuf = (char *)realloc(inbuf, inbuflen);
                    assert(inbuf); // Probably unrecoverable if realloc fails
                                   // anyway.
                }

                instate = FILL_BUF;
                /* FALLTHROUGH */
            } else {
                break;
            }
            /* FALLTHROUGH */
        case FILL_BUF:

            if (inofs - intogo >= inmsglen) {
                instate = HAS_MSG;
            }
            /* FALLTHROUGH */
            else {
                break;
            }

        case HAS_MSG:
            /* handled elsewere */
            break;

        case ERROR: return false;
    }

    return true;
}

void
MsgChannel::chopInput()
{
    /* Make buffer smaller, if there's much already read in front
       of it, or it is cheap to do.  */
    if (intogo > 8192 || inofs - intogo <= 16) {
        if (inofs - intogo != 0) {
            memmove(inbuf, inbuf + intogo, inofs - intogo);
        }

        inofs -= intogo;
        intogo = 0;
    }
}

void
MsgChannel::chopOutput()
{
    if (msgofs > 8192 || msgtogo <= 16) {
        if (msgtogo) {
            memmove(msgbuf, msgbuf + msgofs, msgtogo);
        }

        msgofs = 0;
    }
}

void
MsgChannel::writeFull(const void * _buf, size_t count)
{
    if (msgtogo + count >= msgbuflen) {
        /* Realloc to a multiple of 128.  */
        msgbuflen = (msgtogo + count + 127) & ~(size_t)127;
        msgbuf = (char *)realloc(msgbuf, msgbuflen);
        assert(msgbuf); // Probably unrecoverable if realloc fails anyway.
    }

    std::memcpy(msgbuf + msgtogo, _buf, count);
    msgtogo += count;
}

bool
MsgChannel::flushWritebuf(bool blocking)
{
    const char * buf = msgbuf + msgofs;
    bool         error = false;

    while (msgtogo) {
        int           send_errno;
        static size_t max_write_size = get_max_write_size();
#ifdef MSG_NOSIGNAL
        ssize_t ret =
            send(fd, buf, std::min(msgtogo, max_write_size), MSG_NOSIGNAL);
        send_errno = errno;
#else
        void (*oldsigpipe)(int);

        oldsigpipe = signal(SIGPIPE, SIG_IGN);
        ssize_t ret = send(fd, buf, std::min(msgtogo, max_write_size), 0);
        send_errno = errno;
        signal(SIGPIPE, oldsigpipe);
#endif

        if (ret < 0) {
            if (send_errno == EINTR) {
                continue;
            }

            /* If we want to write blocking, but couldn't write anything,
               select on the fd.  */
            if (blocking && (send_errno == EAGAIN || send_errno == ENOTCONN ||
                             send_errno == EWOULDBLOCK)) {
                int ready;

                for (;;) {
                    pollfd pfd;
                    pfd.fd = fd;
                    pfd.events = POLLOUT;
                    ready = poll(&pfd, 1, 30 * 1000);

                    if (ready < 0 && errno == EINTR) {
                        continue;
                    }

                    break;
                }

                /* socket ready now for writing ? */
                if (ready > 0) {
                    continue;
                }
                if (ready == 0) {
                    log_error()
                        << "timed out while trying to send data" << std::endl;
                }

                /* Timeout or real error --> error.  */
            }

            errno = send_errno;
            log_perror("flushWritebuf() failed");
            error = true;
            break;
        } else if (ret == 0) {
            // EOF while writing --> error
            error = true;
            break;
        }

        msgtogo -= ret;
        buf += ret;
    }

    msgofs = buf - msgbuf;
    chopOutput();
    if (error) {
        setError();
        return false;
    }
    return true;
}

MsgChannel &
MsgChannel::operator>>(uint32_t & buf)
{
    if (inofs >= intogo + 4) {
        if (ptrdiff_t(inbuf + intogo) % 4) {
            uint32_t t_buf[1];
            std::memcpy(t_buf, inbuf + intogo, 4);
            buf = t_buf[0];
        } else {
            buf = *(uint32_t *)(inbuf + intogo);
        }

        intogo += 4;
        buf = ntohl(buf);
    } else {
        buf = 0;
    }

    return *this;
}

MsgChannel &
MsgChannel::operator<<(uint32_t i)
{
    i = htonl(i);
    writeFull(&i, 4);
    return *this;
}

MsgChannel &
MsgChannel::operator>>(std::string & s)
{
    char * buf;
    // len is including the (also saved) 0 Byte
    uint32_t len;
    *this >> len;

    if (!len || len > inofs - intogo) {
        s = "";
    } else {
        buf = inbuf + intogo;
        intogo += len;
        s = buf;
    }

    return *this;
}

MsgChannel &
MsgChannel::operator<<(const std::string & s)
{
    uint32_t len = 1 + s.length();
    *this << len;
    writeFull(s.c_str(), len);
    return *this;
}

MsgChannel &
MsgChannel::operator>>(std::list<std::string> & l)
{
    uint32_t len;
    l.clear();
    *this >> len;

    while (len--) {
        std::string s;
        *this >> s;
        l.push_back(std::move(s));

        if (inofs == intogo) {
            break;
        }
    }

    return *this;
}

MsgChannel &
MsgChannel::operator<<(const std::list<std::string> & l)
{
    *this << static_cast<uint32_t>(l.size());

    for (const std::string & s : l) {
        *this << s;
    }

    return *this;
}

void
MsgChannel::writeEnvironments(const Environments & envs)
{
    *this << envs.size();

    for (const std::pair<std::string, std::string> & env : envs) {
        *this << env.first;
        *this << env.second;
    }
}

void
MsgChannel::readEnvironments(Environments & envs)
{
    envs.clear();
    uint32_t count;
    *this >> count;

    for (unsigned int i = 0; i < count; i++) {
        std::string plat;
        std::string vers;
        *this >> plat;
        *this >> vers;
        envs.emplace_back(std::piecewise_construct,
                          std::forward_as_tuple(std::move(plat)),
                          std::forward_as_tuple(std::move(vers)));
    }
}

void
MsgChannel::readcompressed(std::vector<uint8_t> & buffer, size_t & _clen)
{
    buffer.clear();

    lzo_uint uncompressed_len;
    lzo_uint compressed_len;
    uint32_t tmp;
    *this >> tmp;
    uncompressed_len = tmp;
    *this >> tmp;
    compressed_len = tmp;

    uint32_t proto = C_LZO;
    if (IS_PROTOCOL_40(this)) {
        *this >> proto;
        if (proto != C_LZO && proto != C_ZSTD) {
            log_error() << "Unknown compression protocol " << proto
                        << std::endl;
            _clen = compressed_len;
            setError();
            return;
        }
    }

    /* If there was some input, but nothing compressed,
       or lengths are bigger than the whole chunk message
       or we don't have everything to uncompress, there was an error.  */
    if (uncompressed_len > MAX_MSG_SIZE || compressed_len > (inofs - intogo) ||
        (uncompressed_len && !compressed_len) ||
        inofs < intogo + compressed_len) {
        log_error() << "failure in readcompressed() length checking"
                    << std::endl;
        _clen = compressed_len;
        setError();
        return;
    }

    buffer.resize(uncompressed_len);

    if (proto == C_ZSTD && uncompressed_len && compressed_len) {
        const void * compressed_buf = inbuf + intogo;
        size_t       ret = ZSTD_decompress(
            buffer.data(), uncompressed_len, compressed_buf, compressed_len);
        if (ZSTD_isError(ret)) {
            log_error() << "internal error - decompression of data from "
                        << dump().c_str()
                        << " failed: " << ZSTD_getErrorName(ret) << std::endl;
            buffer.clear();
        }
    } else if (proto == C_LZO && uncompressed_len && compressed_len) {
        const lzo_bytep compressed_buf =
            reinterpret_cast<lzo_bytep>(inbuf + intogo);
        std::array<uint8_t, LZO1X_MEM_DECOMPRESS> wrkmem{};
        int ret = lzo1x_decompress(compressed_buf,
                                   compressed_len,
                                   buffer.data(),
                                   &uncompressed_len,
                                   static_cast<lzo_voidp>(wrkmem.data()));

        assert(ret == LZO_E_OK && uncompressed_len == buffer.size());
        (void)ret;
    }

    /* Read over everything used, _also_ if there was some error.
       If we couldn't decode it now, it won't get better in the future,
       so just ignore this hunk.  */
    intogo += compressed_len;
    _clen = compressed_len;
}

void
MsgChannel::writecompressed(const unsigned char * in_buf,
                            size_t                _in_len,
                            size_t &              _out_len)
{
    uint32_t proto = C_LZO;
    if (IS_PROTOCOL_40(this))
        proto = C_ZSTD;

    lzo_uint in_len = _in_len;
    lzo_uint out_len = _out_len;
    if (proto == C_LZO)
        out_len = in_len + in_len / 64 + 16 + 3;
    else if (proto == C_ZSTD)
        out_len = ZSTD_COMPRESSBOUND(in_len);
    *this << in_len;
    size_t msgtogo_old = msgtogo;
    *this << static_cast<uint32_t>(0);

    if (IS_PROTOCOL_40(this))
        *this << proto;

    if (msgtogo + out_len >= msgbuflen) {
        /* Realloc to a multiple of 128.  */
        msgbuflen = (msgtogo + out_len + 127) & ~(size_t)127;
        msgbuf = (char *)realloc(msgbuf, msgbuflen);
        assert(msgbuf); // Probably unrecoverable if realloc fails anyway.
    }

    if (proto == C_LZO) {
        lzo_byte * out_buf = (lzo_byte *)(msgbuf + msgtogo);
        lzo_voidp  wrkmem = (lzo_voidp)malloc(LZO1X_MEM_COMPRESS);
        int ret = lzo1x_1_compress(in_buf, in_len, out_buf, &out_len, wrkmem);
        free(wrkmem);

        if (ret != LZO_E_OK) {
            /* this should NEVER happen */
            log_error() << "internal error - compression failed: " << ret
                        << std::endl;
            out_len = 0;
        }
    } else if (proto == C_ZSTD) {
        void * out_buf = msgbuf + msgtogo;
        size_t ret =
            ZSTD_compress(out_buf, out_len, in_buf, in_len, zstd_compression());
        if (ZSTD_isError(ret)) {
            /* this should NEVER happen */
            log_error() << "internal error - compression failed: "
                        << ZSTD_getErrorName(ret) << std::endl;
            out_len = 0;
        }

        out_len = ret;
    }

    uint32_t _olen = htonl(out_len);
    if (out_len > MAX_MSG_SIZE) {
        log_error() << "internal error - size of compressed message to write "
                       "exceeds max size:"
                    << out_len << std::endl;
    }
    std::memcpy(msgbuf + msgtogo_old, &_olen, 4);
    msgtogo += out_len;
    _out_len = out_len;
}

void
MsgChannel::readLine(std::string & line)
{
    /* XXX handle DOS and MAC line endings and null bytes as std::string
     * endings.  */
    if (true || inofs < intogo) {
        line = "";
    } else {
        line = std::string(inbuf + intogo, inmsglen);
        intogo += inmsglen;

        while (intogo < inofs && inbuf[intogo] < ' ') {
            intogo++;
        }
    }
}

void
MsgChannel::writeLine(const std::string & line)
{
    size_t len = line.length();
    writeFull(line.c_str(), len);

    if (line[len - 1] != '\n') {
        char c = '\n';
        writeFull(&c, 1);
    }
}

void
MsgChannel::setError(bool silent)
{
    if (instate == ERROR) {
        return;
    }
    if (!silent && !set_error_recursion) {
        trace() << "setting error state for channel " << dump() << std::endl;
        // After the state is set to error, getMsg() will not return anything
        // anymore, so try to fetch last status from the other side, if
        // available.
        set_error_recursion = true;
        auto msg = getMsg(2, true);

        auto * stmsg = ext::get_if<StatusTextMsg>(&msg);
        if (stmsg != nullptr) {
            log_error() << "remote status: " << stmsg->text << std::endl;
        }
        set_error_recursion = false;
    }
    instate = ERROR;
    eof_ = true;
}

MsgChannel *
Service::createChannel(const std::string & hostname,
                       unsigned short      p,
                       int                 timeout)
{
    int                remote_fd;
    struct sockaddr_in remote_addr;

    if ((remote_fd = prepare_connect(hostname, p, remote_addr)) < 0) {
        return nullptr;
    }

    if (timeout) {
        if (!connect_async(remote_fd,
                           (struct sockaddr *)&remote_addr,
                           sizeof(remote_addr),
                           timeout)) {
            return nullptr; // remote_fd is already closed
        }
    } else {
        int i = 2048;
        setsockopt(remote_fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));

        if (connect(remote_fd,
                    (struct sockaddr *)&remote_addr,
                    sizeof(remote_addr)) < 0) {
            log_perror_trace("connect");
            trace() << "connect failed on " << hostname << std::endl;
            if (-1 == close(remote_fd) && (errno != EBADF)) {
                log_perror("close failed");
            }
            return nullptr;
        }
    }

    trace() << "connected to " << hostname << std::endl;
    return createChannel(
        remote_fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
}

MsgChannel *
Service::createChannel(const std::string & socket_path)
{
    int                remote_fd;
    struct sockaddr_un remote_addr;

    if ((remote_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        log_perror("socket()");
        return nullptr;
    }

    remote_addr.sun_family = AF_UNIX;
    strncpy(remote_addr.sun_path,
            socket_path.c_str(),
            sizeof(remote_addr.sun_path) - 1);
    remote_addr.sun_path[sizeof(remote_addr.sun_path) - 1] = '\0';
    if (socket_path.length() > sizeof(remote_addr.sun_path) - 1) {
        log_error() << "socket_path path too long for sun_path" << std::endl;
    }

    if (connect(remote_fd,
                (struct sockaddr *)&remote_addr,
                sizeof(remote_addr)) < 0) {
        log_perror_trace("connect");
        trace() << "connect failed on " << socket_path << std::endl;
        if ((-1 == close(remote_fd)) && (errno != EBADF)) {
            log_perror("close failed");
        }
        return nullptr;
    }

    trace() << "connected to " << socket_path << std::endl;
    return createChannel(
        remote_fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
}

bool
MsgChannel::eq_ip(const MsgChannel & s) const
{
    struct sockaddr_in *s1, *s2;
    s1 = (struct sockaddr_in *)addr;
    s2 = (struct sockaddr_in *)s.addr;
    return (addr_len == s.addr_len &&
            memcmp(&s1->sin_addr, &s2->sin_addr, sizeof(s1->sin_addr)) == 0);
}

MsgChannel *
Service::createChannel(int fd, struct sockaddr * _a, socklen_t _l)
{
    MsgChannel * c = new MsgChannel(fd, _a, _l);

    if (!c->waitProtocol()) {
        delete c;
        c = nullptr;
    }

    return c;
}

MsgChannel::MsgChannel(int _fd, struct sockaddr * _a, socklen_t _l) : fd(_fd)
{
    addr_len = (sizeof(struct sockaddr) > _l) ? sizeof(struct sockaddr) : _l;

    if (addr_len && _a) {
        addr = (struct sockaddr *)malloc(addr_len);
        std::memcpy(addr, _a, _l);
        if (addr->sa_family == AF_UNIX) {
            name = "local unix domain socket";
        } else {
            char buf[16384] = "";
            if (int error = getnameinfo(
                    addr, _l, buf, sizeof(buf), nullptr, 0, NI_NUMERICHOST))
                log_error() << "getnameinfo(): " << error << std::endl;
            name = buf;
        }
    } else {
        addr = nullptr;
        name = "";
    }

    // not using new/delete because of the need of realloc()
    msgbuf = (char *)malloc(128);
    msgbuflen = 128;
    msgofs = 0;
    msgtogo = 0;
    inbuf = (char *)malloc(128);
    inbuflen = 128;
    inofs = 0;
    intogo = 0;
    eof_ = false;
    set_error_recursion = false;
    maximum_remote_protocol = -1;

    int on = 1;

    if (!setsockopt(_fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&on, sizeof(on))) {
#if defined(TCP_KEEPIDLE) || defined(TCPCTL_KEEPIDLE)
#if defined(TCP_KEEPIDLE)
        int keepidle = TCP_KEEPIDLE;
#else
        int keepidle = TCPCTL_KEEPIDLE;
#endif

        int sec;
        sec = MAX_SCHEDULER_PING - 3 * MAX_SCHEDULER_PONG;
        setsockopt(_fd, IPPROTO_TCP, keepidle, (char *)&sec, sizeof(sec));
#endif

#if defined(TCP_KEEPINTVL) || defined(TCPCTL_KEEPINTVL)
#if defined(TCP_KEEPINTVL)
        int keepintvl = TCP_KEEPINTVL;
#else
        int keepintvl = TCPCTL_KEEPINTVL;
#endif

        sec = MAX_SCHEDULER_PONG;
        setsockopt(_fd, IPPROTO_TCP, keepintvl, (char *)&sec, sizeof(sec));
#endif

#ifdef TCP_KEEPCNT
        sec = 3;
        setsockopt(_fd, IPPROTO_TCP, TCP_KEEPCNT, (char *)&sec, sizeof(sec));
#endif
    }

#ifdef TCP_USER_TIMEOUT
    int timeout =
        3 * 3 *
        1000; // matches the timeout part of keepalive above, in milliseconds
    setsockopt(
        _fd, IPPROTO_TCP, TCP_USER_TIMEOUT, (char *)&timeout, sizeof(timeout));
#endif

    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        log_perror("MsgChannel fcntl()");
    }

    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        log_perror("MsgChannel fcntl() 2");
    }

    instate = NEED_PROTO;
    protocol = -1;
    unsigned char vers[4] = {PROTOCOL_VERSION, 0, 0, 0};
    // writeuint32 ((uint32_t) PROTOCOL_VERSION);
    writeFull(vers, 4);

    if (!flushWritebuf(true)) {
        protocol = 0; // unusable
        setError();
    }

    last_talk = time(nullptr);
}

MsgChannel::~MsgChannel()
{
    if (fd >= 0) {
        if ((-1 == close(fd)) && (errno != EBADF)) {
            log_perror("close failed");
        }
    }

    fd = -1;

    if (msgbuf) {
        free(msgbuf);
    }

    if (inbuf) {
        free(inbuf);
    }

    if (addr) {
        free(addr);
    }
}

std::string
MsgChannel::dump() const
{
    return name + ": (" + char((int)instate + 'A') +
           " eof: " + char(eof_ + '0') + ")";
}

/* Wait blocking until the protocol setup for this channel is complete.
   Returns false if an error occurred.  */
bool
MsgChannel::waitProtocol()
{
    /* protocol is 0 if we couldn't send our initial protocol version.  */
    if (protocol == 0 || instate == ERROR) {
        return false;
    }

    while (instate == NEED_PROTO) {
        pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, 15 * 1000); // 15s

        if (ret < 0 && errno == EINTR) {
            continue;
        }

        if (ret == 0) {
            log_warning() << "no response within timeout" << std::endl;
            setError();
            return false; /* timeout. Consider it a fatal error. */
        }

        if (ret < 0) {
            log_perror("select in waitProtocol()");
            setError();
            return false;
        }

        if (!readSome() || eof_) {
            return false;
        }
    }

    return true;
}

void
MsgChannel::setBulkTransfer()
{
    if (fd < 0) {
        return;
    }

    int i = 0;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&i, sizeof(i));

    // would be nice but not portable across non-linux
#ifdef __linux__
    i = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_CORK, (char *)&i, sizeof(i));
#endif
    i = 65536;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));
}

/* This waits indefinitely (well, TIMEOUT seconds) for a complete
   message to arrive.  Returns false if there was some error.  */
bool
MsgChannel::waitMsg(int timeout)
{
    if (instate == ERROR) {
        return false;
    }

    if (hasMsg()) {
        return true;
    }

    if (!readSome()) {
        trace() << "!readSome\n";
        setError();
        return false;
    }

    if (timeout <= 0) {
        // trace() << "timeout <= 0\n";
        return hasMsg();
    }

    while (!hasMsg()) {
        pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;

        if (poll(&pfd, 1, timeout * 1000) <= 0) {
            if (errno == EINTR) {
                continue;
            }

            /* Either timeout or real error.  For this function also
               a timeout is an error.  */
            return false;
        }

        if (!readSome()) {
            trace() << "!readSome 2\n";
            setError();
            return false;
        }
    }

    return true;
}

Msg
MsgChannel::getMsg(int timeout, bool eofAllowed)
{
    if (!waitMsg(timeout)) {
        // trace() << "!waitMsg()\n";
        return ext::monostate{};
    }

    /* If we've seen the EOF, and we don't have a complete message,
       then we won't see it anymore.  Return that to the caller.
       Don't use hasMsg() here, as it returns true for eof.  */
    if (eof()) {
        if (!eofAllowed) {
            trace() << "saw eof without complete msg! " << instate << std::endl;
            setError();
        }
        return ext::monostate{};
    }

    if (!hasMsg()) {
        trace() << "saw eof without msg! " << eof_ << " " << instate
                << std::endl;
        setError();
        return ext::monostate{};
    }

    size_t intogo_old = intogo;

    uint32_t t;
    *this >> t;
    const auto type = static_cast<MsgType>(t);

    using M = MsgType;
    static const std::unordered_map<MsgType, std::function<Msg()>> msg_map{
        {M::UNKNOWN,
         [this] {
             setError();
             return ext::monostate{};
         }},
        {M::PING, [] { return PingMsg{}; }},
        {M::END, [] { return EndMsg{}; }},
        {M::GET_CS, [] { return GetCSMsg{}; }},
        {M::USE_CS, [] { return UseCSMsg{}; }},
        {M::NO_CS, [] { return NoCSMsg{}; }},
        {M::COMPILE_FILE, [] { return CompileFileMsg{}; }},
        {M::FILE_CHUNK, [] { return FileChunkMsg{}; }},
        {M::COMPILE_RESULT, [] { return CompileResultMsg{}; }},
        {M::JOB_BEGIN, [] { return JobBeginMsg{}; }},
        {M::JOB_DONE, [] { return JobDoneMsg{}; }},
        {M::LOGIN, [] { return LoginMsg{}; }},
        {M::STATS, [] { return StatsMsg{}; }},
        {M::GET_NATIVE_ENV, [] { return GetNativeEnvMsg{}; }},
        {M::USE_NATIVE_ENV, [] { return UseNativeEnvMsg{}; }},
        {M::MON_LOGIN, [] { return MonLoginMsg{}; }},
        {M::MON_GET_CS, [] { return MonGetCSMsg{}; }},
        {M::MON_JOB_BEGIN, [] { return MonJobBeginMsg{}; }},
        {M::MON_JOB_DONE, [] { return MonJobDoneMsg{}; }},
        {M::MON_STATS, [] { return MonStatsMsg{}; }},
        {M::JOB_LOCAL_BEGIN, [] { return JobLocalBeginMsg{}; }},
        {M::JOB_LOCAL_DONE, [] { return JobLocalDoneMsg{}; }},
        {M::MON_LOCAL_JOB_BEGIN, [] { return MonLocalJobBeginMsg{}; }},
        {M::ENV_TRANSFER, [] { return EnvTransferMsg{}; }},
        {M::TEXT_DEPRECATED, [] { return Msg{}; }},
        {M::GET_INTERNAL_STATUS, [] { return GetInternalStatusMsg{}; }},
        {M::STATUS_TEXT, [] { return StatusTextMsg{}; }},
        {M::CONF_CS, [] { return ConfCSMsg{}; }},
        {M::VERIFY_ENV, [] { return VerifyEnvMsg{}; }},
        {M::VERIFY_ENV_RESULT, [] { return VerifyEnvResultMsg{}; }},
        {M::BLACKLIST_HOST_ENV, [] { return BlacklistHostEnvMsg{}; }},
        {M::TIMEOUT, [] { return ext::monostate{}; }}};
    auto it = msg_map.find(type);
    if (it == msg_map.end()) {
        setError();
        return ext::monostate{};
    }

    auto msg = it->second();

    bool fail = ext::visit(ext::make_visitor(
                               [this](ext::monostate & /*unused*/) {
                                   trace() << "no message type" << std::endl;
                                   setError();
                                   return true;
                               },
                               [this](auto & m) {
                                   m.fillFromChannel(this);
                                   return false;
                               }),
                           msg);

    if (fail) {
        return ext::monostate{};
    }

    if (intogo - intogo_old != inmsglen) {
        log_error()
            << "internal error - message not read correctly, message size "
            << inmsglen << " read " << (intogo - intogo_old) << std::endl;
        setError();
        return ext::monostate{};
    }

    instate = NEED_LEN;
    updateState();

    return msg;
}

bool
MsgChannel::sendMsg(const Msg & msg, int flags)
{
    if (instate == ERROR) {
        return false;
    }
    if (instate == NEED_PROTO && !waitProtocol()) {
        return false;
    }

    chopOutput();
    size_t msgtogo_old = msgtogo;

    // Length placeholder
    *this << static_cast<uint32_t>(0);

    bool fail = ext::visit(ext::make_visitor(
                               [this](const ext::monostate & /*unused*/) {
                                   trace() << "no message type" << std::endl;
                                   setError();
                                   return true;
                               },
                               [this](const auto & m) {
                                   using T = std::decay_t<decltype(m)>;

                                   *this << static_cast<uint32_t>(
                                       icecream::type_id<T>());

                                   m.sendToChannel(this);
                                   return false;
                               }),
                           msg);
    if (fail) {
        return false;
    }

    const uint32_t out_len = msgtogo - msgtogo_old - 4;
    if (out_len > MAX_MSG_SIZE) {
        log_error()
            << "internal error - size of message to write exceeds max size:"
            << out_len << std::endl;
        setError();
        return false;
    }
    const uint32_t len = htonl(out_len);
    std::memcpy(msgbuf + msgtogo_old, &len, 4);

    if ((flags & SendBulkOnly) && msgtogo < 4096) {
        return true;
    }

    return flushWritebuf((flags & SendBlocking));
}

void
Broadcasts::broadcastSchedulerVersion(int          scheduler_port,
                                      const char * netname,
                                      time_t       starttime)
{
    // Code for older schedulers than version 38. Has endianness problems, the
    // message size is not BROAD_BUFLEN and the netname is possibly not
    // null-terminated.
    const char        length_netname = strlen(netname);
    const int         schedbuflen = 5 + sizeof(uint64_t) + length_netname;
    std::vector<char> buf(schedbuflen, 0);
    buf[0] = 'I';
    buf[1] = 'C';
    buf[2] = 'E';
    buf[3] = PROTOCOL_VERSION;
    uint64_t tmp_time = starttime;
    std::memcpy(&buf[4], &tmp_time, sizeof(uint64_t));
    buf[4 + sizeof(uint64_t)] = length_netname;
    strncpy(&buf[5 + sizeof(uint64_t)], netname, length_netname - 1);
    buf[schedbuflen - 1] = '\0';
    broadcastData(scheduler_port, buf.data(), schedbuflen);
    // Latest version.
    buf.resize(BROAD_BUFLEN);
    std::fill_n(buf.begin(), BROAD_BUFLEN, 0);
    buf[0] = 'I';
    buf[1] = 'C';
    buf[2] = 'F'; // one up
    buf[3] = PROTOCOL_VERSION;
    uint32_t tmp_time_low = starttime & 0xffffffffUL;
    uint32_t tmp_time_high = uint64_t(starttime) >> 32;
    tmp_time_low = htonl(tmp_time_low);
    tmp_time_high = htonl(tmp_time_high);
    std::memcpy(&buf[4], &tmp_time_high, sizeof(uint32_t));
    std::memcpy(&buf[4 + sizeof(uint32_t)], &tmp_time_low, sizeof(uint32_t));
    const int OFFSET = 4 + 2 * sizeof(uint32_t);
    snprintf(&buf[OFFSET], BROAD_BUFLEN - OFFSET, "%s", netname);
    buf[BROAD_BUFLEN - 1] = 0;
    broadcastData(scheduler_port, buf.data(), BROAD_BUFLEN);
}

bool
Broadcasts::isSchedulerVersion(const char * buf, int buflen)
{
    if (buflen != BROAD_BUFLEN) {
        return false;
    }
    // Ignore versions older than 38, they are older than us anyway, so not
    // interesting.
    return buf[0] == 'I' && buf[1] == 'C' && buf[2] == 'F';
}

void
Broadcasts::getSchedulerVersionData(const char *  buf,
                                    int *         protocol,
                                    time_t *      time,
                                    std::string * netname)
{
    assert(isSchedulerVersion(buf, BROAD_BUFLEN));
    const unsigned char other_scheduler_protocol = buf[3];
    uint32_t            tmp_time_low, tmp_time_high;
    std::memcpy(&tmp_time_high, buf + 4, sizeof(uint32_t));
    std::memcpy(&tmp_time_low, buf + 4 + sizeof(uint32_t), sizeof(uint32_t));
    tmp_time_low = ntohl(tmp_time_low);
    tmp_time_high = ntohl(tmp_time_high);
    time_t other_time = (uint64_t(tmp_time_high) << 32) | tmp_time_low;

    std::string recv_netname(buf + 4 + 2 * sizeof(uint32_t));
    if (protocol != nullptr) {
        *protocol = other_scheduler_protocol;
    }

    if (time != nullptr) {
        *time = other_time;
    }

    if (netname != nullptr) {
        *netname = recv_netname;
    }
}

void
Broadcasts::broadcastData(int port, const char * buf, int len)
{
    int fd = open_send_broadcast(port, buf, len);
    if (fd >= 0) {
        if ((-1 == close(fd)) && (errno != EBADF)) {
            log_perror("close failed");
        }
    }
    int secondPort = get_second_port_for_debug(port);
    if (secondPort > 0) {
        int fd2 = open_send_broadcast(secondPort, buf, len);
        if (fd2 >= 0) {
            if ((-1 == close(fd2)) && (errno != EBADF)) {
                log_perror("close failed");
            }
        }
    }
}

DiscoverSched::DiscoverSched(const std::string & _netname,
                             int                 _timeout,
                             const std::string & _schedname,
                             int                 port)
    : netname(_netname),
      schedname(_schedname),
      timeout(_timeout),
      ask_fd(-1),
      ask_second_fd(-1),
      sport(port),
      best_version(0),
      best_start_time(0),
      best_port(0),
      multiple(false)
{
    time0 = time(nullptr);

    if (schedname.empty()) {
        const char * get = getenv("ICECC_SCHEDULER");
        if (get == nullptr)
            get = getenv("USE_SCHEDULER");

        if (get) {
            std::string scheduler = get;
            size_t      colon = scheduler.rfind(':');
            if (colon == std::string::npos) {
                schedname = scheduler;
            } else {
                schedname = scheduler.substr(0, colon);
                sport = atoi(scheduler.substr(colon + 1).c_str());
            }
        }
    }

    if (netname.empty()) {
        netname = "ICECREAM";
    }
    if (sport == 0) {
        sport = 8765;
    }

    if (!schedname.empty()) {
        netname = ""; // take whatever the machine is giving us
        attemptSchedulerConnect();
    } else {
        sendSchedulerDiscovery(PROTOCOL_VERSION);
    }
}

DiscoverSched::~DiscoverSched()
{
    if (ask_fd >= 0) {
        if ((-1 == close(ask_fd)) && (errno != EBADF)) {
            log_perror("close failed");
        }
    }
    if (ask_second_fd >= 0) {
        if ((-1 == close(ask_second_fd)) && (errno != EBADF)) {
            log_perror("close failed");
        }
    }
}

bool
DiscoverSched::timedOut()
{
    return (time(nullptr) - time0 >= timeout);
}

void
DiscoverSched::attemptSchedulerConnect()
{
    time0 = time(nullptr) + MAX_SCHEDULER_PONG;
    log_info() << "scheduler is on " << schedname << ":" << sport << " (net "
               << netname << ")" << std::endl;

    if ((ask_fd = prepare_connect(schedname, sport, remote_addr)) >= 0) {
        fcntl(ask_fd, F_SETFL, O_NONBLOCK);
    }
}

void
DiscoverSched::sendSchedulerDiscovery(int version)
{
    assert(version < 128);
    char buf = version;
    ask_fd = open_send_broadcast(sport, &buf, 1);
    int secondPort = get_second_port_for_debug(sport);
    if (secondPort > 0)
        ask_second_fd = open_send_broadcast(secondPort, &buf, 1);
}

bool
DiscoverSched::isSchedulerDiscovery(const char * buf,
                                    int          buflen,
                                    int *        daemon_version)
{
    if (buflen != 1)
        return false;
    if (daemon_version != nullptr) {
        *daemon_version = buf[0];
    }
    return true;
}

namespace {
const int BROAD_BUFLEN = 268;
const int BROAD_BUFLEN_OLD_2 = 32;
const int BROAD_BUFLEN_OLD_1 = 16;
} // namespace

int
DiscoverSched::prepareBroadcastReply(char *       buf,
                                     const char * netname,
                                     time_t       starttime)
{
    if (buf[0] < 33) { // old client
        buf[0]++;
        std::memset(buf + 1, 0, BROAD_BUFLEN_OLD_1 - 1);
        snprintf(buf + 1, BROAD_BUFLEN_OLD_1 - 1, "%s", netname);
        buf[BROAD_BUFLEN_OLD_1 - 1] = 0;
        return BROAD_BUFLEN_OLD_1;
    } else if (buf[0] < 36) {
        // This is like 36, but 36 silently changed the size of BROAD_BUFLEN
        // from 32 to 268. Since getBroadAnswer() explicitly null-terminates
        // the data, this wouldn't lead to those receivers reading a shorter
        // std::string that would not be null-terminated, but still, this is
        // what versions 33-35 actually worked with.
        buf[0] += 2;
        std::memset(buf + 1, 0, BROAD_BUFLEN_OLD_2 - 1);
        uint32_t tmp_version = PROTOCOL_VERSION;
        uint64_t tmp_time = starttime;
        std::memcpy(buf + 1, &tmp_version, sizeof(uint32_t));
        std::memcpy(buf + 1 + sizeof(uint32_t), &tmp_time, sizeof(uint64_t));
        const int OFFSET = 1 + sizeof(uint32_t) + sizeof(uint64_t);
        snprintf(buf + OFFSET, BROAD_BUFLEN_OLD_2 - OFFSET, "%s", netname);
        buf[BROAD_BUFLEN_OLD_2 - 1] = 0;
        return BROAD_BUFLEN_OLD_2;
    } else if (buf[0] < 38) { // exposes endianess because of not using htonl()
        buf[0] += 2;
        std::memset(buf + 1, 0, BROAD_BUFLEN - 1);
        uint32_t tmp_version = PROTOCOL_VERSION;
        uint64_t tmp_time = starttime;
        std::memcpy(buf + 1, &tmp_version, sizeof(uint32_t));
        std::memcpy(buf + 1 + sizeof(uint32_t), &tmp_time, sizeof(uint64_t));
        const int OFFSET = 1 + sizeof(uint32_t) + sizeof(uint64_t);
        snprintf(buf + OFFSET, BROAD_BUFLEN - OFFSET, "%s", netname);
        buf[BROAD_BUFLEN - 1] = 0;
        return BROAD_BUFLEN;
    } else { // latest version
        buf[0] += 3;
        std::memset(buf + 1, 0, BROAD_BUFLEN - 1);
        uint32_t tmp_version = PROTOCOL_VERSION;
        uint32_t tmp_time_low = starttime & 0xffffffffUL;
        uint32_t tmp_time_high = uint64_t(starttime) >> 32;
        tmp_version = htonl(tmp_version);
        tmp_time_low = htonl(tmp_time_low);
        tmp_time_high = htonl(tmp_time_high);
        std::memcpy(buf + 1, &tmp_version, sizeof(uint32_t));
        std::memcpy(
            buf + 1 + sizeof(uint32_t), &tmp_time_high, sizeof(uint32_t));
        std::memcpy(
            buf + 1 + 2 * sizeof(uint32_t), &tmp_time_low, sizeof(uint32_t));
        const int OFFSET = 1 + 3 * sizeof(uint32_t);
        snprintf(buf + OFFSET, BROAD_BUFLEN - OFFSET, "%s", netname);
        buf[BROAD_BUFLEN - 1] = 0;
        return BROAD_BUFLEN;
    }
}

void
DiscoverSched::getBroadData(const char *  buf,
                            const char ** out_name,
                            int *         out_version,
                            time_t *      out_start_time)
{
    if (buf[0] == PROTOCOL_VERSION + 1) {
        // Scheduler version 32 or older, didn't send us its version, assume
        // it's 32.
        if (out_name != nullptr) {
            *out_name = buf + 1;
        }

        if (out_version != nullptr) {
            *out_version = 32;
        }

        if (out_start_time != nullptr) {
            *out_start_time = 0; // Unknown too.
        }
    } else if (buf[0] == PROTOCOL_VERSION + 2) {
        if (out_version != nullptr) {
            uint32_t tmp_version;
            std::memcpy(&tmp_version, buf + 1, sizeof(uint32_t));
            *out_version = tmp_version;
        }
        if (out_start_time != nullptr) {
            uint64_t tmp_time;
            std::memcpy(
                &tmp_time, buf + 1 + sizeof(uint32_t), sizeof(uint64_t));
            *out_start_time = tmp_time;
        }
        if (out_name != nullptr)
            *out_name = buf + 1 + sizeof(uint32_t) + sizeof(uint64_t);
    } else if (buf[0] == PROTOCOL_VERSION + 3) {
        if (out_version != nullptr) {
            uint32_t tmp_version;
            std::memcpy(&tmp_version, buf + 1, sizeof(uint32_t));
            *out_version = ntohl(tmp_version);
        }
        if (out_start_time != nullptr) {
            uint32_t tmp_time_low, tmp_time_high;
            std::memcpy(
                &tmp_time_high, buf + 1 + sizeof(uint32_t), sizeof(uint32_t));
            std::memcpy(&tmp_time_low,
                        buf + 1 + 2 * sizeof(uint32_t),
                        sizeof(uint32_t));
            tmp_time_low = ntohl(tmp_time_low);
            tmp_time_high = ntohl(tmp_time_high);
            *out_start_time = (uint64_t(tmp_time_high) << 32) | tmp_time_low;
        }
        if (out_name != nullptr) {
            *out_name = buf + 1 + 3 * sizeof(uint32_t);
        }
    } else {
        abort();
    }
}

MsgChannel *
DiscoverSched::tryGetScheduler()
{
    if (schedname.empty()) {
        socklen_t remote_len;
        char      buf2[BROAD_BUFLEN];
        /* Try to get the scheduler with the newest version, and if there
           are several with the same version, choose the one that's been running
           for the longest time. It should work like this (and it won't work
           perfectly if there are schedulers and/or daemons with old (<33)
           version):

           Whenever a daemon starts, it broadcasts for a scheduler. Schedulers
           all see the broadcast and respond with their version, start time and
           netname. Here we select the best one. If a new scheduler is started,
           it'll broadcast its version and all other schedulers will drop their
           daemon connections if they have an older version. If the best
           scheduler quits, all daemons will get their connections closed and
           will re-discover and re-connect.
        */

        /* Read/test all packages arrived until now.  */
        while (getBroadAnswer(ask_fd,
                              0 /*timeout*/,
                              buf2,
                              (struct sockaddr_in *)&remote_addr,
                              &remote_len) ||
               (ask_second_fd != -1 &&
                getBroadAnswer(ask_second_fd,
                               0 /*timeout*/,
                               buf2,
                               (struct sockaddr_in *)&remote_addr,
                               &remote_len))) {
            int          version;
            time_t       start_time;
            const char * name;
            getBroadData(buf2, &name, &version, &start_time);
            if (strcasecmp(netname.c_str(), name) == 0) {
                if (version >= 128 || version < 1) {
                    log_warning() << "Ignoring bogus version " << version
                                  << " from scheduler found at "
                                  << inet_ntoa(remote_addr.sin_addr) << ":"
                                  << ntohs(remote_addr.sin_port) << std::endl;
                    continue;
                } else if (version < 33) {
                    log_info() << "Suitable scheduler found at "
                               << inet_ntoa(remote_addr.sin_addr) << ":"
                               << ntohs(remote_addr.sin_port)
                               << " (unknown version)" << std::endl;
                } else {
                    log_info() << "Suitable scheduler found at "
                               << inet_ntoa(remote_addr.sin_addr) << ":"
                               << ntohs(remote_addr.sin_port)
                               << " (version: " << version << ")" << std::endl;
                }
                if (best_version != 0)
                    multiple = true;
                if (best_version < version ||
                    (best_version == version && best_start_time > start_time)) {
                    best_schedname = inet_ntoa(remote_addr.sin_addr);
                    best_port = ntohs(remote_addr.sin_port);
                    best_version = version;
                    best_start_time = start_time;
                }
            } else {
                log_info() << "Ignoring scheduler at "
                           << inet_ntoa(remote_addr.sin_addr) << ":"
                           << ntohs(remote_addr.sin_port)
                           << " because of a different netname (" << name << ")"
                           << std::endl;
            }
        }

        if (timedOut()) {
            if (best_version == 0) {
                return nullptr;
            }
            schedname = best_schedname;
            sport = best_port;
            if (multiple)
                log_info() << "Selecting scheduler at " << schedname << ":"
                           << sport << std::endl;

            if (-1 == close(ask_fd)) {
                log_perror("close failed");
            }
            ask_fd = -1;
            if (get_second_port_for_debug(sport) > 0) {
                if (-1 == close(ask_second_fd)) {
                    log_perror("close failed");
                }
                ask_second_fd = -1;
            } else {
                assert(ask_second_fd == -1);
            }
            attemptSchedulerConnect();

            if (ask_fd >= 0) {
                int status = connect(ask_fd,
                                     (struct sockaddr *)&remote_addr,
                                     sizeof(remote_addr));

                if (status == 0 || (status < 0 && (errno == EISCONN ||
                                                   errno == EINPROGRESS))) {
                    int fd = ask_fd;
                    ask_fd = -1;
                    return Service::createChannel(
                        fd,
                        (struct sockaddr *)&remote_addr,
                        sizeof(remote_addr));
                }
            }
        }
    } else if (ask_fd >= 0) {
        assert(ask_second_fd == -1);
        int status = connect(
            ask_fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));

        if (status == 0 || (status < 0 && errno == EISCONN)) {
            int fd = ask_fd;
            ask_fd = -1;
            return Service::createChannel(
                fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
        }
    }

    return nullptr;
}

bool
DiscoverSched::getBroadAnswer(int                  ask_fd,
                              int                  timeout,
                              char *               buf2,
                              struct sockaddr_in * remote_addr,
                              socklen_t *          remote_len)
{
    char   buf = PROTOCOL_VERSION;
    pollfd pfd;
    assert(ask_fd > 0);
    pfd.fd = ask_fd;
    pfd.events = POLLIN;
    errno = 0;

    if (poll(&pfd, 1, timeout) <= 0 || (pfd.revents & POLLIN) == 0) {
        /* Normally this is a timeout, i.e. no scheduler there.  */
        if (errno && errno != EINTR) {
            log_perror("waiting for scheduler");
        }

        return false;
    }

    *remote_len = sizeof(struct sockaddr_in);

    int len = recvfrom(ask_fd,
                       buf2,
                       BROAD_BUFLEN,
                       0,
                       (struct sockaddr *)remote_addr,
                       remote_len);
    if (len != BROAD_BUFLEN && len != BROAD_BUFLEN_OLD_1 &&
        len != BROAD_BUFLEN_OLD_2) {
        log_perror("getBroadAnswer recvfrom()");
        return false;
    }

    if (!((len == BROAD_BUFLEN_OLD_1 &&
           buf2[0] == buf + 1) // PROTOCOL <= 32 scheduler
          || (len == BROAD_BUFLEN_OLD_2 &&
              buf2[0] == buf + 2) // PROTOCOL >= 33 && < 36 scheduler
          || (len == BROAD_BUFLEN &&
              buf2[0] == buf + 2) // PROTOCOL >= 36 && < 38 scheduler
          || (len == BROAD_BUFLEN &&
              buf2[0] == buf + 3))) { // PROTOCOL >= 38 scheduler
        log_error() << "Wrong scheduler discovery answer (size " << len
                    << ", mark " << int(buf2[0]) << ")" << std::endl;
        return false;
    }

    buf2[len - 1] = 0;
    return true;
}

std::list<std::string>
DiscoverSched::getNetnames(int timeout, int port)
{
    std::list<std::string> l;
    int                    ask_fd;
    struct sockaddr_in     remote_addr;
    socklen_t              remote_len;
    time_t                 time0 = time(nullptr);

    char buf = PROTOCOL_VERSION;
    ask_fd = open_send_broadcast(port, &buf, 1);

    do {
        char buf2[BROAD_BUFLEN];
        bool first = true;
        /* Wait at least two seconds to give all schedulers a chance to answer
           (unless that'd be longer than the timeout).*/
        time_t timeout_time = time(nullptr) + std::min(2 + 1, timeout);

        /* Read/test all arriving packages.  */
        while (
            getBroadAnswer(
                ask_fd, first ? timeout : 0, buf2, &remote_addr, &remote_len) &&
            time(nullptr) < timeout_time) {
            first = false;
            const char * name;
            getBroadData(buf2, &name, nullptr, nullptr);
            l.emplace_back(name);
        }
    } while (time(nullptr) - time0 < (timeout / 1000));

    if ((-1 == close(ask_fd)) && (errno != EBADF)) {
        log_perror("close failed");
    }
    return l;
}

std::list<std::string>
get_netnames(int timeout, int port)
{
    return DiscoverSched::getNetnames(timeout, port);
}

GetCSMsg::GetCSMsg(const Environments & envs,
                   const std::string &  f,
                   CompileJob::Language _lang,
                   unsigned int         _count,
                   std::string          _target,
                   unsigned int         _arg_flags,
                   const std::string &  host,
                   int                  _minimal_host_version,
                   unsigned int         _required_features,
                   int                  _niceness,
                   unsigned int         _client_count)
    : versions(envs),
      filename(f),
      lang(_lang),
      count(_count),
      target(_target),
      arg_flags(_arg_flags),
      client_id(0),
      preferred_host(host),
      minimal_host_version(_minimal_host_version),
      required_features(_required_features),
      client_count(_client_count),
      niceness(_niceness)
{
    // These have been introduced in protocol version 42.
    if (required_features & (NODE_FEATURE_ENV_XZ | NODE_FEATURE_ENV_ZSTD))
        minimal_host_version = std::max(minimal_host_version, 42);
    assert(_niceness >= 0 && _niceness <= 20);
}

void
GetCSMsg::fillFromChannel(MsgChannel * c)
{
    c->readEnvironments(versions);
    *c >> filename;
    uint32_t _lang;
    *c >> _lang;
    *c >> count;
    *c >> target;
    lang = static_cast<CompileJob::Language>(_lang);
    *c >> arg_flags;
    *c >> client_id;
    preferred_host = std::string();

    if (IS_PROTOCOL_22(c)) {
        *c >> preferred_host;
    }

    minimal_host_version = 0;
    if (IS_PROTOCOL_31(c)) {
        uint32_t ign;
        *c >> ign;
        // Versions 31-33 had this as a separate field, now set a minimal
        // remote version if needed.
        if (ign != 0 && minimal_host_version < 31)
            minimal_host_version = 31;
    }
    if (IS_PROTOCOL_34(c)) {
        uint32_t version;
        *c >> version;
        minimal_host_version = std::max(minimal_host_version, int(version));
    }

    if (IS_PROTOCOL_39(c)) {
        *c >> client_count;
    }

    required_features = 0;
    if (IS_PROTOCOL_42(c)) {
        *c >> required_features;
    }

    niceness = 0;
    if (IS_PROTOCOL_43(c)) {
        *c >> niceness;
    }
}

void
GetCSMsg::sendToChannel(MsgChannel * c) const
{
    c->writeEnvironments(versions);
    *c << shorten_filename(filename);
    *c << static_cast<uint32_t>(lang);
    *c << count;
    *c << target;
    *c << arg_flags;
    *c << client_id;

    if (IS_PROTOCOL_22(c)) {
        *c << preferred_host;
    }

    if (IS_PROTOCOL_31(c)) {
        *c << uint32_t(minimal_host_version >= 31 ? 1 : 0);
    }
    if (IS_PROTOCOL_34(c)) {
        *c << minimal_host_version;
    }

    if (IS_PROTOCOL_39(c)) {
        *c << client_count;
    }
    if (IS_PROTOCOL_42(c)) {
        *c << required_features;
    }
    if (IS_PROTOCOL_43(c)) {
        *c << niceness;
    }
}

void
UseCSMsg::fillFromChannel(MsgChannel * c)
{
    *c >> job_id;
    *c >> port;
    *c >> hostname;
    *c >> host_platform;
    *c >> got_env;
    *c >> client_id;

    if (IS_PROTOCOL_28(c)) {
        *c >> matched_job_id;
    } else {
        matched_job_id = 0;
    }
}

void
UseCSMsg::sendToChannel(MsgChannel * c) const
{
    *c << job_id;
    *c << port;
    *c << hostname;
    *c << host_platform;
    *c << got_env;
    *c << client_id;

    if (IS_PROTOCOL_28(c)) {
        *c << matched_job_id;
    }
}

void
NoCSMsg::fillFromChannel(MsgChannel * c)
{
    *c >> job_id;
    *c >> client_id;
}

void
NoCSMsg::sendToChannel(MsgChannel * c) const
{
    *c << job_id;
    *c << client_id;
}

void
CompileFileMsg::fillFromChannel(MsgChannel * c)
{
    uint32_t    id, lang;
    std::string version;
    *c >> lang;
    *c >> id;
    ArgumentsList l;
    if (IS_PROTOCOL_41(c)) {
        std::list<std::string> largs;
        *c >> largs;
        // Whe compiling remotely, we no longer care about the
        // ArgumentType::REMOTE vs ArgumentType::REST difference, so treat them
        // all as ArgumentType::REMOTE.
        for (auto it = largs.begin(); it != largs.end(); ++it) {
            l.append(*it, ArgumentType::REMOTE);
        }
    } else {
        std::list<std::string> _l1, _l2;
        *c >> _l1;
        *c >> _l2;
        for (auto it = _l1.begin(); it != _l1.end(); ++it) {
            l.append(*it, ArgumentType::REMOTE);
        }
        for (auto it = _l2.begin(); it != _l2.end(); ++it) {
            l.append(*it, ArgumentType::REST);
        }
    }
    *c >> version;
    job->setLanguage((CompileJob::Language)lang);
    job->setJobID(id);

    job->setFlags(l);
    job->setEnvironmentVersion(version);

    std::string target;
    *c >> target;
    job->setTargetPlatform(target);

    if (IS_PROTOCOL_30(c)) {
        std::string compilerName;
        *c >> compilerName;
        job->setCompilerName(compilerName);
    }
    if (IS_PROTOCOL_34(c)) {
        std::string inputFile;
        std::string workingDirectory;
        *c >> inputFile;
        *c >> workingDirectory;
        job->setInputFile(inputFile);
        job->setWorkingDirectory(workingDirectory);
    }
    if (IS_PROTOCOL_35(c)) {
        std::string outputFile;
        uint32_t    dwarfFissionEnabled = 0;
        *c >> outputFile;
        *c >> dwarfFissionEnabled;
        job->setOutputFile(outputFile);
        job->setDwarfFissionEnabled(dwarfFissionEnabled);
    }
}

void
CompileFileMsg::sendToChannel(MsgChannel * c) const
{
    *c << static_cast<uint32_t>(job->language());
    *c << job->jobID();

    if (IS_PROTOCOL_41(c)) {
        // By the time we're compiling, the args are all ArgumentType::REMOTE or
        // ArgumentType::REST and we no longer care about the differences, but
        // we may care about the ordering. So keep them all in one list.
        *c << job->nonLocalFlags();
    } else {
        if (IS_PROTOCOL_30(c)) {
            *c << job->remoteFlags();
        } else {
            if (job->compilerName().find("clang") != std::string::npos) {
                // Hack for compilerwrapper.
                std::list<std::string> flags = job->remoteFlags();
                flags.emplace_front("clang");
                *c << flags;
            } else {
                *c << job->remoteFlags();
            }
        }
        *c << job->restFlags();
    }

    *c << job->environmentVersion();
    *c << job->targetPlatform();

    if (IS_PROTOCOL_30(c)) {
        *c << remoteCompilerName();
    }
    if (IS_PROTOCOL_34(c)) {
        *c << job->inputFile();
        *c << job->workingDirectory();
    }
    if (IS_PROTOCOL_35(c)) {
        *c << job->outputFile();
        *c << static_cast<uint32_t>(job->dwarfFissionEnabled());
    }
}

// Environments created by icecc-create-env always use the same binary name
// for compilers, so even if local name was e.g. c++, remote needs to
// be g++ (before protocol version 30 remote CS even had /usr/bin/{gcc|g++}
// hardcoded).  For clang, the binary is just clang for both C/C++.
std::string
CompileFileMsg::remoteCompilerName() const
{
    if (job->compilerName().find("clang") != std::string::npos) {
        return "clang";
    }

    return job->language() == CompileJob::Lang_CXX ? "g++" : "gcc";
}

void
FileChunkMsg::fillFromChannel(MsgChannel * c)
{
    buffer.clear();

    c->readcompressed(buffer, compressed);
}

void
FileChunkMsg::sendToChannel(MsgChannel * c) const
{
    c->writecompressed(buffer.data(), buffer.size(), compressed);
}

void
CompileResultMsg::fillFromChannel(MsgChannel * c)
{
    uint32_t _status = 0;
    *c >> err;
    *c >> out;
    *c >> _status;
    status = _status;
    uint32_t was = 0;
    *c >> was;
    was_out_of_memory = was;
    if (IS_PROTOCOL_35(c)) {
        uint32_t dwo = 0;
        *c >> dwo;
        have_dwo_file = dwo;
    }
}

void
CompileResultMsg::sendToChannel(MsgChannel * c) const
{
    *c << err;
    *c << out;
    *c << status;
    *c << static_cast<uint32_t>(was_out_of_memory);
    if (IS_PROTOCOL_35(c)) {
        *c << static_cast<uint32_t>(have_dwo_file);
    }
}

void
JobBeginMsg::fillFromChannel(MsgChannel * c)
{
    *c >> job_id;
    *c >> stime;
    if (IS_PROTOCOL_39(c)) {
        *c >> client_count;
    }
}

void
JobBeginMsg::sendToChannel(MsgChannel * c) const
{
    *c << job_id;
    *c << stime;
    if (IS_PROTOCOL_39(c)) {
        *c << client_count;
    }
}

void
JobLocalBeginMsg::fillFromChannel(MsgChannel * c)
{
    *c >> stime;
    *c >> outfile;
    *c >> id;
}

void
JobLocalBeginMsg::sendToChannel(MsgChannel * c) const
{
    *c << stime;
    *c << outfile;
    *c << id;
}

void
JobLocalDoneMsg::fillFromChannel(MsgChannel * c)
{
    *c >> job_id;
}

void
JobLocalDoneMsg::sendToChannel(MsgChannel * c) const
{
    *c << job_id;
}

JobDoneMsg::JobDoneMsg(int          id,
                       int          exit,
                       unsigned int _flags,
                       unsigned int _client_count)
    : exitcode(exit), flags(_flags), job_id(id), client_count(_client_count)
{
    real_msec = 0;
    user_msec = 0;
    sys_msec = 0;
    pfaults = 0;
    in_compressed = 0;
    in_uncompressed = 0;
    out_compressed = 0;
    out_uncompressed = 0;
}

void
JobDoneMsg::fillFromChannel(MsgChannel * c)
{
    uint32_t _exitcode = 255;
    *c >> job_id;
    *c >> _exitcode;
    *c >> real_msec;
    *c >> user_msec;
    *c >> sys_msec;
    *c >> pfaults;
    *c >> in_compressed;
    *c >> in_uncompressed;
    *c >> out_compressed;
    *c >> out_uncompressed;
    *c >> flags;
    exitcode = (int)_exitcode;
    // Older versions used this special exit code to identify
    // EndJob messages for jobs with unknown job id.
    if (!IS_PROTOCOL_39(c) && exitcode == 200) {
        flags |= UnknownJobId;
    }
    if (IS_PROTOCOL_39(c)) {
        *c >> client_count;
    }
}

void
JobDoneMsg::sendToChannel(MsgChannel * c) const
{
    *c << job_id;
    if (!IS_PROTOCOL_39(c) && (flags & UnknownJobId)) {
        *c << static_cast<uint32_t>(200);
    } else {
        *c << static_cast<uint32_t>(exitcode);
    }
    *c << real_msec;
    *c << user_msec;
    *c << sys_msec;
    *c << pfaults;
    *c << in_compressed;
    *c << in_uncompressed;
    *c << out_compressed;
    *c << out_uncompressed;
    *c << flags;
    if (IS_PROTOCOL_39(c)) {
        *c << client_count;
    }
}

void
JobDoneMsg::setUnknownJobClientId(uint32_t clientId)
{
    flags |= UnknownJobId;
    job_id = clientId;
}

uint32_t
JobDoneMsg::unknownJobClientId() const
{
    if (flags & UnknownJobId) {
        return job_id;
    }
    return 0;
}

void
JobDoneMsg::setJobId(uint32_t jobId)
{
    job_id = jobId;
    flags &= ~static_cast<uint32_t>(UnknownJobId);
}

LoginMsg::LoginMsg(uint32_t            myport,
                   const std::string & _nodename,
                   const std::string & _host_platform,
                   unsigned int        myfeatures)
    : port(myport),
      max_kids(0),
      noremote(false),
      chroot_possible(false),
      nodename(_nodename),
      host_platform(_host_platform),
      supported_features(myfeatures)
{
#ifdef HAVE_LIBCAP_NG
    chroot_possible = capng_have_capability(CAPNG_EFFECTIVE, CAP_SYS_CHROOT);
#else
    // check if we're root
    chroot_possible = (geteuid() == 0);
#endif
}

void
LoginMsg::fillFromChannel(MsgChannel * c)
{
    *c >> port;
    *c >> max_kids;
    c->readEnvironments(envs);
    *c >> nodename;
    *c >> host_platform;
    uint32_t net_chroot_possible = 0;
    *c >> net_chroot_possible;
    chroot_possible = net_chroot_possible != 0;
    uint32_t net_noremote = 0;

    if (IS_PROTOCOL_26(c)) {
        *c >> net_noremote;
    }

    noremote = (net_noremote != 0);

    supported_features = 0;
    if (IS_PROTOCOL_42(c)) {
        *c >> supported_features;
    }
}

void
LoginMsg::sendToChannel(MsgChannel * c) const
{
    *c << port;
    *c << max_kids;
    c->writeEnvironments(envs);
    *c << nodename;
    *c << host_platform;
    *c << chroot_possible;

    if (IS_PROTOCOL_26(c)) {
        *c << noremote;
    }
    if (IS_PROTOCOL_42(c)) {
        *c << supported_features;
    }
}

void
ConfCSMsg::fillFromChannel(MsgChannel * c)
{
    *c >> max_scheduler_pong;
    *c >> max_scheduler_ping;
    std::string bench_source; // unused, kept for backwards compatibility
    *c >> bench_source;
}

void
ConfCSMsg::sendToChannel(MsgChannel * c) const
{
    *c << max_scheduler_pong;
    *c << max_scheduler_ping;
    std::string bench_source;
    *c << bench_source;
}

void
StatsMsg::fillFromChannel(MsgChannel * c)
{
    *c >> load;
    *c >> loadAvg1;
    *c >> loadAvg5;
    *c >> loadAvg10;
    *c >> freeMem;
}

void
StatsMsg::sendToChannel(MsgChannel * c) const
{
    *c << load;
    *c << loadAvg1;
    *c << loadAvg5;
    *c << loadAvg10;
    *c << freeMem;
}

void
GetNativeEnvMsg::fillFromChannel(MsgChannel * c)
{
    if (IS_PROTOCOL_32(c)) {
        *c >> compiler;
        *c >> extrafiles;
    }
    compression = std::string();
    if (IS_PROTOCOL_42(c))
        *c >> compression;
}

void
GetNativeEnvMsg::sendToChannel(MsgChannel * c) const
{
    if (IS_PROTOCOL_32(c)) {
        *c << compiler;
        *c << extrafiles;
    }
    if (IS_PROTOCOL_42(c))
        *c << compression;
}

void
UseNativeEnvMsg::fillFromChannel(MsgChannel * c)
{
    *c >> nativeVersion;
}

void
UseNativeEnvMsg::sendToChannel(MsgChannel * c) const
{
    *c << nativeVersion;
}

void
EnvTransferMsg::fillFromChannel(MsgChannel * c)
{
    *c >> name;
    *c >> target;
}

void
EnvTransferMsg::sendToChannel(MsgChannel * c) const
{
    *c << name;
    *c << target;
}

void
MonGetCSMsg::fillFromChannel(MsgChannel * c)
{
    if (IS_PROTOCOL_29(c)) {
        *c >> filename;
        uint32_t _lang;
        *c >> _lang;
        lang = static_cast<CompileJob::Language>(_lang);
    } else {
        GetCSMsg::fillFromChannel(c);
    }

    *c >> job_id;
    *c >> clientid;
}

void
MonGetCSMsg::sendToChannel(MsgChannel * c) const
{
    if (IS_PROTOCOL_29(c)) {
        *c << shorten_filename(filename);
        *c << static_cast<uint32_t>(lang);
    } else {
        GetCSMsg::sendToChannel(c);
    }

    *c << job_id;
    *c << clientid;
}

void
MonJobBeginMsg::fillFromChannel(MsgChannel * c)
{
    *c >> job_id;
    *c >> stime;
    *c >> hostid;
}

void
MonJobBeginMsg::sendToChannel(MsgChannel * c) const
{
    *c << job_id;
    *c << stime;
    *c << hostid;
}

void
MonLocalJobBeginMsg::fillFromChannel(MsgChannel * c)
{
    *c >> hostid;
    *c >> job_id;
    *c >> stime;
    *c >> file;
}

void
MonLocalJobBeginMsg::sendToChannel(MsgChannel * c) const
{
    *c << hostid;
    *c << job_id;
    *c << stime;
    *c << shorten_filename(file);
}

void
MonStatsMsg::fillFromChannel(MsgChannel * c)
{
    *c >> hostid;
    *c >> statmsg;
}

void
MonStatsMsg::sendToChannel(MsgChannel * c) const
{
    *c << hostid;
    *c << statmsg;
}

void
StatusTextMsg::fillFromChannel(MsgChannel * c)
{
    *c >> text;
}

void
StatusTextMsg::sendToChannel(MsgChannel * c) const
{
    *c << text;
}

void
VerifyEnvMsg::fillFromChannel(MsgChannel * c)
{
    *c >> environment;
    *c >> target;
}

void
VerifyEnvMsg::sendToChannel(MsgChannel * c) const
{
    *c << environment;
    *c << target;
}

void
VerifyEnvResultMsg::fillFromChannel(MsgChannel * c)
{
    uint32_t read_ok;
    *c >> read_ok;
    ok = read_ok != 0;
}

void
VerifyEnvResultMsg::sendToChannel(MsgChannel * c) const
{
    *c << uint32_t(ok);
}

void
BlacklistHostEnvMsg::fillFromChannel(MsgChannel * c)
{
    *c >> environment;
    *c >> target;
    *c >> hostname;
}

void
BlacklistHostEnvMsg::sendToChannel(MsgChannel * c) const
{
    *c << environment;
    *c << target;
    *c << hostname;
}

/*
vim:cinoptions={.5s,g0,p5,t0,(0,^-0.5s,n-0.5s:tw=78:cindent:sw=4:
*/
