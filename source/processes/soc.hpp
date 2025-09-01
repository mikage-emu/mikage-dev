#pragma once

#include "fake_process.hpp"

namespace HLE {

namespace OS {

// Extracted from https://github.com/devkitPro/libctru/blob/faf5162b60eab5402d3839330f985b84382df76c/libctru/source/services/soc/soc_common.c#L10
enum SocketErrors {
    CTR_ESUCCESS, // 0
    CTR_E2BIG,
    CTR_EACCES,
    CTR_EADDRINUSE,
    CTR_EADDRNOTAVAIL,
    CTR_EAFNOSUPPORT, // 5
    CTR_EAGAIN,
    CTR_EALREADY,
    CTR_EBADF,
    CTR_EBADMSG,
    CTR_EBUSY, // 10
    CTR_ECANCELED,
    CTR_ECHILD,
    CTR_ECONNABORTED,
    CTR_ECONNREFUSED,
    CTR_ECONNRESET, // 15
    CTR_EDEADLK,
    CTR_EDESTADDRREQ,
    CTR_EDOM,
    CTR_EDQUOT,
    CTR_EEXIST, // 20
    CTR_EFAULT,
    CTR_EFBIG,
    CTR_EHOSTUNREACH,
    CTR_EIDRM,
    CTR_EILSEQ, // 25
    CTR_EINPROGRESS,
    CTR_EINTR,
    CTR_EINVAL,
    CTR_EIO,
    CTR_EISCONN, // 30
    CTR_EISDIR,
    CTR_ELOOP,
    CTR_EMFILE,
    CTR_EMLINK,
    CTR_EMSGSIZE, // 35
    CTR_EMULTIHOP,
    CTR_ENAMETOOLONG,
    CTR_ENETDOWN,
    CTR_ENETRESET,
    CTR_ENETUNREACH, // 40
    CTR_ENFILE,
    CTR_ENOBUFS,
    CTR_ENODATA,
    CTR_ENODEV,
    CTR_ENOENT, // 45
    CTR_ENOEXEC,
    CTR_ENOLCK,
    CTR_ENOLINK,
    CTR_ENOMEM,
    CTR_ENOMSG, // 50
    CTR_ENOPROTOOPT,
    CTR_ENOSPC,
    CTR_ENOSR,
    CTR_ENOSTR,
    CTR_ENOSYS, // 55
    CTR_ENOTCONN,
    CTR_ENOTDIR,
    CTR_ENOTEMPTY,
    CTR_ENOTSOCK,
    CTR_ENOTSUP, // 60
    CTR_ENOTTY,
    CTR_ENXIO,
    CTR_EOPNOTSUPP,
    CTR_EOVERFLOW,
    CTR_EPERM, // 65
    CTR_EPIPE,
    CTR_EPROTO,
    CTR_EPROTONOSUPPORT,
    CTR_EPROTOTYPE,
    CTR_ERANGE, // 70
    CTR_EROFS,
    CTR_ESPIPE,
    CTR_ESRCH,
    CTR_ESTALE,
    CTR_ETIME, // 75
    CTR_ETIMEDOUT,
};

enum AddrInfoErrors {
    CTR_EAI_FAMILY = 303,
    CTR_EAI_MEMORY,
    CTR_EAI_NONAME,
    CTR_EAI_SOCKTYPE = 307,
};

enum AddrInfoFlags {
    CTR_AI_PASSIVE = 1,
    CTR_AI_CANONNAME = 2,
    CTR_AI_NUMERICHOST = 4,
};

enum NameInfoFlags {
    CTR_NI_NOFQDN = 1,
    CTR_NI_NUMERICHOST = 2,
    CTR_NI_NAMEREQD = 4,
};

enum SockOptLevels {
    CTR_SOL_IP = 0,
    CTR_SOL_TCP = 6,
    CTR_SOL_CONFIG = 0xFFFE, // Only used for NetworkOpt commands
    CTR_SOL_SOCKET = 0xFFFF,
};

enum SockOptNames {
    // SOL_IP optnames
    CTR_IP_TOS = 7,
    CTR_IP_TTL,
    CTR_IP_MULTICAST_LOOP,
    CTR_IP_MULTICAST_TTL,
    CTR_IP_ADD_MEMBERSHIP,
    CTR_IP_DROP_MEMBERSHIP,

    // SOL_TCP optnames
    CTR_TCP_NODELAY = 0x2001,
    CTR_TCP_MAXSEG = 0x2002,

    // SOL_SOCKET optnames
    CTR_SO_REUSEADDR = 0x4,
    CTR_SO_LINGER = 0x80,
    CTR_SO_OOBINLINE = 0x100,
    CTR_SO_SNDBUF = 0x1001,
    CTR_SO_RCVBUF = 0x1002,
    CTR_SO_SNDLOWAT = 0x1003,
    CTR_SO_RCVLOWAT = 0x1004,
    CTR_SO_TYPE = 0x1008,
    CTR_SO_ERROR = 0x1009,
};

// Extracted from https://github.com/devkitPro/libctru/blob/faf5162b60eab5402d3839330f985b84382df76c/libctru/include/3ds/services/soc.h#L14
enum NetworkOptNames {
    NETOPT_MAC_ADDRESS     = 0x1004, ///< The mac address of the interface
    NETOPT_ARP_TABLE       = 0x3002, ///< The ARP table
    NETOPT_IP_INFO         = 0x4003, ///< The current IP setup
    NETOPT_IP_MTU          = 0x4004, ///< The value of the IP MTU
    NETOPT_ROUTING_TABLE   = 0x4006, ///< The routing table
    NETOPT_UDP_NUMBER      = 0x8002, ///< The number of sockets in the UDP table
    NETOPT_UDP_TABLE       = 0x8003, ///< The table of opened UDP sockets
    NETOPT_TCP_NUMBER      = 0x9002, ///< The number of sockets in the TCP table
    NETOPT_TCP_TABLE       = 0x9003, ///< The table of opened TCP sockets
    NETOPT_DNS_TABLE       = 0xB003, ///< The table of the DNS servers
    NETOPT_DHCP_LEASE_TIME = 0xC001, ///< The DHCP lease time remaining, in seconds
};

enum SocketDomain {
    CTR_AF_UNSPEC = 0,
    CTR_AF_INET = 2,
    CTR_AF_INET6 = 23,
};

enum SockType {
    CTR_SOCK_STREAM = 1,
    CTR_SOCK_DGRAM,
};

enum SockProtocol {
    CTR_IPPROTO_IP = 0,
    CTR_IPPROTO_TCP = 6,
    CTR_IPPROTO_UDP = 17,
};

enum FcntlCmd {
    CTR_F_GETFL = 3,
    CTR_F_SETFL,
};

enum SendRecvFlags {
    CTR_MSG_OOB = 0x1,
    CTR_MSG_PEEK = 0x2,
    CTR_MSG_DONTWAIT = 0x4,
};

enum SocketShutdownHow {
    CTR_SHUT_RD,
    CTR_SHUT_WR,
    CTR_SHUT_RDWR,
};

// NOTE: The official sysmodule doesn't use flag 0x4 and doesn't have POLLERR or POLLHUP
enum PollEvents {
    CTR_POLLOUT = 0x1,
    CTR_POLLPRI = 0x2,
    CTR_POLLWRNORM = 0x8,
    CTR_POLLWRBAND = 0x10,
    CTR_POLLNVAL = 0x20,
};

constexpr int CTR_FLAGS_ALL = CTR_MSG_OOB | CTR_MSG_PEEK | CTR_MSG_DONTWAIT;
constexpr int CTR_O_NONBLOCK = 0x4;

template<> std::shared_ptr<WrappedFakeProcess> CreateFakeProcessViaContext<struct FakeSOC>(OS&, Interpreter::Setup&, uint32_t, const std::string&);

}  // namespace OS

}  // namespace HLE
