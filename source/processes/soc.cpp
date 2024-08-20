#include "ipc.hpp"
#include "os.hpp"
#include "soc.hpp"

#include "../platform/soc.hpp"
#include "os_hypervisor.hpp"
#include "platform/ipc.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <future>
#include <framework/exceptions.hpp>

#include <ifaddrs.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>

namespace HLE {

namespace OS {

static const std::unordered_map<int, SocketErrors> error_map {
    {E2BIG, CTR_E2BIG},
    {EACCES, CTR_EACCES},
    {EADDRINUSE, CTR_EADDRINUSE},
    {EADDRNOTAVAIL, CTR_EADDRNOTAVAIL},
    {EAFNOSUPPORT, CTR_EAFNOSUPPORT},
    {EAGAIN, CTR_EAGAIN},
    {EALREADY, CTR_EALREADY},
    {EBADF, CTR_EBADF},
    {EBADMSG, CTR_EBADMSG},
    {EBUSY, CTR_EBUSY},
    {ECANCELED, CTR_ECANCELED},
    {ECHILD, CTR_ECHILD},
    {ECONNABORTED, CTR_ECONNABORTED},
    {ECONNREFUSED, CTR_ECONNREFUSED},
    {ECONNRESET, CTR_ECONNRESET},
    {EDEADLK, CTR_EDEADLK},
    {EDESTADDRREQ, CTR_EDESTADDRREQ},
    {EDOM, CTR_EDOM},
    {EDQUOT, CTR_EDQUOT},
    {EEXIST, CTR_EEXIST},
    {EFAULT, CTR_EFAULT},
    {EFBIG, CTR_EFBIG},
    {EHOSTUNREACH, CTR_EHOSTUNREACH},
    {EIDRM, CTR_EIDRM},
    {EILSEQ, CTR_EILSEQ},
    {EINPROGRESS, CTR_EINPROGRESS},
    {EINTR, CTR_EINTR},
    {EINVAL, CTR_EINVAL},
    {EIO, CTR_EIO},
    {EISCONN, CTR_EISCONN},
    {EISDIR, CTR_EISDIR},
    {ELOOP, CTR_ELOOP},
    {EMFILE, CTR_EMFILE},
    {EMLINK, CTR_EMLINK},
    {EMSGSIZE, CTR_EMSGSIZE},
    {EMULTIHOP, CTR_EMULTIHOP},
    {ENAMETOOLONG, CTR_ENAMETOOLONG},
    {ENETDOWN, CTR_ENETDOWN},
    {ENETRESET, CTR_ENETRESET},
    {ENETUNREACH, CTR_ENETUNREACH},
    {ENFILE, CTR_ENFILE},
    {ENOBUFS, CTR_ENOBUFS},
    {ENODATA, CTR_ENODATA},
    {ENODEV, CTR_ENODEV},
    {ENOENT, CTR_ENOENT},
    {ENOEXEC, CTR_ENOEXEC},
    {ENOLCK, CTR_ENOLCK},
    {ENOLINK, CTR_ENOLINK},
    {ENOMEM, CTR_ENOMEM},
    {ENOMSG, CTR_ENOMSG},
    {ENOPROTOOPT, CTR_ENOPROTOOPT},
    {ENOSPC, CTR_ENOSPC},
    {ENOSR, CTR_ENOSR},
    {ENOSTR, CTR_ENOSTR},
    {ENOSYS, CTR_ENOSYS},
    {ENOTCONN, CTR_ENOTCONN},
    {ENOTDIR, CTR_ENOTDIR},
    {ENOTEMPTY, CTR_ENOTEMPTY},
    {ENOTSOCK, CTR_ENOTSOCK},
    {ENOTSUP, CTR_ENOTSUP},
    {ENOTTY, CTR_ENOTTY},
    {ENXIO, CTR_ENXIO},
    {EOPNOTSUPP, CTR_EOPNOTSUPP},
    {EOVERFLOW, CTR_EOVERFLOW},
    {EPERM, CTR_EPERM},
    {EPIPE, CTR_EPIPE},
    {EPROTO, CTR_EPROTO},
    {EPROTONOSUPPORT, CTR_EPROTONOSUPPORT},
    {EPROTOTYPE, CTR_EPROTOTYPE},
    {ERANGE, CTR_ERANGE},
    {EROFS, CTR_EROFS},
    {ESPIPE, CTR_ESPIPE},
    {ESRCH, CTR_ESRCH},
    {ESTALE, CTR_ESTALE},
    {ETIME, CTR_ETIME},
    {ETIMEDOUT, CTR_ETIMEDOUT}
};

static int ErrorNativeTo3DS(int error) {
    auto found = error_map.find(error);
    if (found != error_map.end())
        return -found->second;

    // The error doesn't have a known translation
    throw Mikage::Exceptions::NotImplemented("Unhandled socket error: {}", error);
}

static int AddrInfoErrorNativeTo3DS(int error) {
    switch (error) {
    case EAI_FAMILY:
        return -CTR_EAI_FAMILY;
    case EAI_MEMORY:
        return -CTR_EAI_MEMORY;
    case EAI_NONAME:
        return -CTR_EAI_NONAME;
    case EAI_SOCKTYPE:
        return -CTR_EAI_SOCKTYPE;
    case EAI_SYSTEM:
        return ErrorNativeTo3DS(errno);
    default:
        // The error doesn't have a known translation
        throw Mikage::Exceptions::NotImplemented("Unhandled addrinfo error: {}", error);
    }
}

static uint32_t AddrInfoFlags3DSToNative(uint32_t flags) {
    uint32_t native_flags = 0;
    if (flags & CTR_AI_PASSIVE)
        native_flags |= AI_PASSIVE;

    if (flags & CTR_AI_CANONNAME)
        native_flags |= AI_CANONNAME;

    if (flags & CTR_AI_NUMERICHOST)
        native_flags |= AI_NUMERICHOST;

    return native_flags;
}

static uint32_t NameInfoFlags3DSToNative(uint32_t flags) {
    uint32_t native_flags = 0;
    if (flags & CTR_NI_NOFQDN)
        native_flags |= NI_NOFQDN;

    if (flags & CTR_NI_NUMERICHOST)
        native_flags |= NI_NUMERICHOST;

    if (flags & CTR_NI_NAMEREQD)
        native_flags |= NI_NAMEREQD;

    return native_flags;
}

static std::tuple<int, int> SockOpt3DSToNative(int level, int optname) {
    switch (level) {
    case CTR_SOL_IP:
        switch (optname) {
        case CTR_IP_TOS:
            return std::make_tuple(SOL_IP, IP_TOS);
        case CTR_IP_TTL:
            return std::make_tuple(SOL_IP, IP_TTL);
        case CTR_IP_MULTICAST_LOOP:
            return std::make_tuple(SOL_IP, IP_MULTICAST_LOOP);
        case CTR_IP_MULTICAST_TTL:
            return std::make_tuple(SOL_IP, IP_MULTICAST_TTL);
        case CTR_IP_ADD_MEMBERSHIP:
            return std::make_tuple(SOL_IP, IP_ADD_MEMBERSHIP);
        case CTR_IP_DROP_MEMBERSHIP:
            return std::make_tuple(SOL_IP, IP_DROP_MEMBERSHIP);
        }
        break;
    case CTR_SOL_TCP:
        switch (optname) {
        case CTR_TCP_NODELAY:
            return std::make_tuple(SOL_TCP, TCP_NODELAY);
        case CTR_TCP_MAXSEG:
            return std::make_tuple(SOL_TCP, TCP_MAXSEG);
        }
        break;
    case CTR_SOL_SOCKET:
        switch (optname) {
        case CTR_SO_REUSEADDR:
            return std::make_tuple(SOL_SOCKET, SO_REUSEADDR);
        case CTR_SO_LINGER:
            return std::make_tuple(SOL_SOCKET, SO_LINGER);
        case CTR_SO_OOBINLINE:
            return std::make_tuple(SOL_SOCKET, SO_OOBINLINE);
        case CTR_SO_SNDBUF:
            return std::make_tuple(SOL_SOCKET, SO_SNDBUF);
        case CTR_SO_RCVBUF:
            return std::make_tuple(SOL_SOCKET, SO_RCVBUF);
        case CTR_SO_SNDLOWAT:
            return std::make_tuple(SOL_SOCKET, SO_SNDLOWAT);
        case CTR_SO_RCVLOWAT:
            return std::make_tuple(SOL_SOCKET, SO_RCVLOWAT);
        case CTR_SO_TYPE:
            return std::make_tuple(SOL_SOCKET, SO_TYPE);
        case CTR_SO_ERROR:
            return std::make_tuple(SOL_SOCKET, SO_ERROR);
        }
        break;
    }

    // The sockopt doesn't have a known translation
    throw Mikage::Exceptions::NotImplemented("Unhandled sockopt: level={:#x}, optname={:#x}", level, optname);
}

static int Domain3DSToNative(uint32_t domain) {
    switch (domain) {
    case CTR_AF_UNSPEC:
        return AF_UNSPEC;
    case CTR_AF_INET: // IPv4
        return AF_INET;
    case CTR_AF_INET6: // IPv6
        return AF_INET6;
    default:
        return -1;
    }
}

static int DomainNativeTo3DS(uint32_t domain) {
    switch (domain) {
    case AF_UNSPEC:
        return CTR_AF_UNSPEC;
    case AF_INET: // IPv4
        return CTR_AF_INET;
    case AF_INET6: // IPv6
        return CTR_AF_INET6;
    default:
        return -1;
    }
}

static int SockType3DSToNative(uint32_t type) {
    switch (type) {
    case CTR_SOCK_STREAM:
        return SOCK_STREAM;
    case CTR_SOCK_DGRAM:
        return SOCK_DGRAM;
    default:
        return -1;
    }
}

static int SockTypeNativeTo3DS(uint32_t type) {
    switch (type) {
    case SOCK_STREAM:
        return CTR_SOCK_STREAM;
    case SOCK_DGRAM:
        return CTR_SOCK_DGRAM;
    default:
        return -1;
    }
}

static int SockProtocol3DSToNative(uint32_t proto) {
    switch (proto) {
    case CTR_IPPROTO_IP:
        return IPPROTO_IP;
    case CTR_IPPROTO_TCP:
        return IPPROTO_TCP;
    case CTR_IPPROTO_UDP:
        return IPPROTO_UDP;
    default:
        return -1;
    }
}

static int SockProtocolNativeTo3DS(uint32_t proto) {
    switch (proto) {
    case IPPROTO_IP:
        return CTR_IPPROTO_IP;
    case IPPROTO_TCP:
        return CTR_IPPROTO_TCP;
    case IPPROTO_UDP:
        return CTR_IPPROTO_UDP;
    default:
        return -1;
    }
}

static int FcntlCmd3DSToNative(uint32_t cmd) {
    switch (cmd) {
    case CTR_F_GETFL:
        return F_GETFL;
    case CTR_F_SETFL:
        return F_SETFL;
    default:
        return -1;
    }
}

static int SendRecvFlags3DSToNative(uint32_t flags) {
    int native_flags = 0;
    if (flags & CTR_MSG_OOB)
        native_flags |= MSG_OOB;

    if (flags & CTR_MSG_PEEK)
        native_flags |= MSG_PEEK;

    if (flags & CTR_MSG_DONTWAIT)
        native_flags |= MSG_DONTWAIT;

    return native_flags;
}

static int ShutdownHow3DSToNative(uint32_t how) {
    switch (how) {
    case CTR_SHUT_RD:
        return SHUT_RD;
    case CTR_SHUT_WR:
        return SHUT_WR;
    case CTR_SHUT_RDWR:
        return SHUT_RDWR;
    default:
        return -1;
    }
}

static uint32_t PollEvents3DSToNative(uint32_t events) {
    uint32_t native_events = 0;
    if (events & CTR_POLLOUT)
        native_events |= POLLOUT;

    if (events & CTR_POLLPRI)
        native_events |= POLLPRI;

    if (events & CTR_POLLWRNORM)
        native_events |= POLLWRNORM;

    if (events & CTR_POLLWRBAND)
        native_events |= POLLWRBAND;

    if (events & CTR_POLLNVAL)
        native_events |= POLLNVAL;

    return native_events;
}

static uint32_t PollEventsNativeTo3DS(uint32_t native_events) {
    uint32_t events = 0;
    if (native_events & POLLOUT)
        events |= CTR_POLLOUT;

    if (native_events & POLLPRI)
        events |= CTR_POLLPRI;

    if (native_events & POLLWRNORM)
        events |= CTR_POLLWRNORM;

    if (native_events & POLLWRBAND)
        events |= CTR_POLLWRBAND;

    if (native_events & POLLNVAL)
        events |= CTR_POLLNVAL;

    return events;
}

struct SocketIPInfo {
    in_addr ip;
    in_addr netmask;
    in_addr broadcast;
};
static_assert(sizeof(SocketIPInfo) == 0xC);

#pragma pack(1)
struct SockAddr3DS {
    uint8_t size;
    uint8_t sa_family;
    union {
        std::array<uint8_t, 0x1A> sa_data;
        struct {
            in_port_t sin_port;
            in_addr sin_addr;
        } in;
        struct {
            in_port_t sin6_port;
            in6_addr sin6_addr;
            uint32_t sin6_flowinfo;
            uint32_t sin6_scope_id;
        } in6;
    };

    SockAddr3DS() = default;
    SockAddr3DS(sockaddr_storage& native) {
        this->sa_family = DomainNativeTo3DS(native.ss_family);
        if (this->sa_family == CTR_AF_INET) {
            this->size = 0x8;
            auto native_in = reinterpret_cast<sockaddr_in&>(native);
            this->in.sin_port = native_in.sin_port;
            this->in.sin_addr = native_in.sin_addr;
        } else if (this->sa_family == CTR_AF_INET6) {
            this->size = 0x1C;
            auto native_in6 = reinterpret_cast<sockaddr_in6&>(native);
            this->in6.sin6_port = native_in6.sin6_port;
            this->in6.sin6_addr = native_in6.sin6_addr;
            this->in6.sin6_flowinfo = native_in6.sin6_flowinfo;
            this->in6.sin6_scope_id = native_in6.sin6_scope_id;
        }
    }

    sockaddr_storage ToNative() {
        sockaddr_storage native{};
        if (this->sa_family == CTR_AF_INET) {
            sockaddr_in* native_in = reinterpret_cast<sockaddr_in*>(&native);
            native_in->sin_family = Domain3DSToNative(this->sa_family);
            native_in->sin_port = this->in.sin_port;
            native_in->sin_addr = this->in.sin_addr;
            return native;
        } else if (this->sa_family == CTR_AF_INET6) {
            sockaddr_in6* native_in6 = reinterpret_cast<sockaddr_in6*>(&native);
            native_in6->sin6_family = Domain3DSToNative(this->sa_family);
            native_in6->sin6_port = this->in6.sin6_port;
            native_in6->sin6_addr = this->in6.sin6_addr;
            native_in6->sin6_flowinfo = this->in6.sin6_flowinfo;
            native_in6->sin6_scope_id = this->in6.sin6_scope_id;
            return native;
        }

        return native;
    }
};
static_assert(sizeof(SockAddr3DS) == 0x1C);
#pragma pack()

struct AddrInfo3DS {
    int32_t ai_flags;
    int32_t ai_family;
    int32_t ai_socktype;
    int32_t ai_protocol;
    uint32_t ai_addrlen;
    std::array<uint8_t, 256> ai_canonname;
    SockAddr3DS ai_addr;

    AddrInfo3DS() = default;
    AddrInfo3DS(addrinfo& addr_info) {
        this->ai_flags = addr_info.ai_flags;
        this->ai_family = DomainNativeTo3DS(addr_info.ai_family);
        this->ai_socktype = SockTypeNativeTo3DS(addr_info.ai_socktype);
        this->ai_protocol = SockProtocolNativeTo3DS(addr_info.ai_protocol);
        this->ai_addrlen = sizeof(SockAddr3DS);

        if (addr_info.ai_canonname != nullptr)
            std::strncpy(reinterpret_cast<char*>(this->ai_canonname.data()), addr_info.ai_canonname, this->ai_canonname.size());

        this->ai_addr = (*reinterpret_cast<sockaddr_storage*>(addr_info.ai_addr));
    }

    addrinfo ToNative() {
        addrinfo addr_info{};
        addr_info.ai_flags = AddrInfoFlags3DSToNative(this->ai_flags);
        addr_info.ai_family = Domain3DSToNative(this->ai_family);
        addr_info.ai_socktype = SockType3DSToNative(this->ai_socktype);
        addr_info.ai_protocol = SockProtocol3DSToNative(this->ai_protocol);

        // NOTE: The original sysmodule ignores the ai_canonname and ai_addr given as input

        return addr_info;
    }
};
static_assert(sizeof(AddrInfo3DS) == 0x130);

struct Linger3DS {
    uint32_t l_onoff;
    uint32_t l_linger;

    Linger3DS() = default;
    Linger3DS(linger l) {
        this->l_onoff = l.l_onoff;
        this->l_linger = l.l_linger;
    }

    linger ToNative() {
        linger l{};
        l.l_onoff = this->l_onoff;
        l.l_linger = this->l_linger;
        return l;
    }
};
static_assert(sizeof(Linger3DS) == 0x8);

struct PollFd3DS {
    uint32_t fd;
    uint32_t events;
    uint32_t revents;

    PollFd3DS() = default;
    PollFd3DS(const pollfd& fd, const bool low_write_priority) {
        this->fd = fd.fd;
        this->events = PollEventsNativeTo3DS(fd.events);
        this->revents = PollEventsNativeTo3DS(fd.revents);

        if (low_write_priority && this->revents & CTR_POLLWRNORM) {
            this->revents &= ~CTR_POLLWRNORM;
            this->revents |= CTR_POLLWRBAND;
        }
    };

    pollfd ToNative(bool& low_write_priority) {
        pollfd fd{};
        fd.fd = this->fd;
        fd.events = PollEvents3DSToNative(this->events);
        fd.revents = PollEvents3DSToNative(this->revents);

        // NOTE: libctru has some poll flags documented wrong. In this context,
        // libctru uses POLLWRBAND as POLLWRNORM and POLLWRNORM is used as
        // POLLERR. This seems to work on hardware because writing "priority
        // data" is almost always available along with writing normal data.
        //
        // This may not always be the case though according to reverse engineering,
        // but it's certain that writing "normal data" MUST be available to be
        // able to write "priority data" too.
        //
        // Since it's currently unknown how the 3DS determines "priority data" can
        // be written, we workaround this by checking for this specific case
        // and marking the priority flag if "normal data" can be written instead
        if (!(fd.events & POLLWRNORM) && fd.events & POLLWRBAND) {
            fd.events |= POLLWRNORM;
            low_write_priority = true;
        }

        return fd;
    }
};
static_assert(sizeof(PollFd3DS) == 0xC);

struct Hostent3DS {
    int16_t h_addrtype;
    int16_t h_length;
    int16_t h_addr_count;
    int16_t h_alias_count;
    std::array<char, 256> h_name;
    std::array<std::array<char, 256>, 24> h_aliases;
    std::array<std::array<char, 16>, 24> h_addr_list;

    Hostent3DS() = default;
    Hostent3DS(const hostent* h) {
        strncpy(this->h_name.data(), h->h_name, this->h_name.size());
        int count = 0;
        if (h->h_aliases != nullptr) {
            for (count = 0; count < 24; count++) {
                if (h->h_aliases[count] == nullptr) break;
                strncpy(this->h_aliases[count].data(), h->h_aliases[count], this->h_aliases[count].size());
            }
        }
        this->h_alias_count = count;

        this->h_addrtype = DomainNativeTo3DS(h->h_addrtype);
        this->h_length = h->h_length;

        if (h->h_addr_list != nullptr) {
            for (count = 0; count < 24; count++) {
                if (h->h_addr_list[count] == nullptr) break;
                strncpy(this->h_addr_list[count].data(), h->h_addr_list[count], this->h_addr_list[count].size());
            }
        }
        this->h_addr_count = count;
    }
};
static_assert(sizeof(Hostent3DS) == 0x1A88);

struct Socket3DS {
    int sockfd;
    ProcessId owner_process;
    bool is_global;
};

struct ProcessContext {
    std::unordered_map<int, Socket3DS> owned_sockets;
    ProcessId process_id;
};

struct FakeSOC {
    IPC::StaticBuffer src_addr_buffer;
    IPC::StaticBuffer dst_addr_buffer;
    IPC::StaticBuffer send_buffer;
    IPC::StaticBuffer name_buffer;
    IPC::StaticBuffer hostent_addr_buffer;
    IPC::StaticBuffer node_buffer;
    IPC::StaticBuffer service_buffer;
    IPC::StaticBuffer nameinfo_addr_buffer;
    IPC::StaticBuffer hints_buffer;
    IPC::StaticBuffer optval_buffer;
    IPC::StaticBuffer pollfds_buffer;

    std::unordered_map<ProcessId, ProcessContext> contexts;
    std::unordered_map<int, Socket3DS> sockets;

    // TODO - It is unclear how this is handled on hardware. It seems like the current process ID
    // is stored on the global context directly, but that doesn't make sense. Alternatively, we use
    // the handle index to determine the client process ID
    std::unordered_map<uint32_t, ProcessId> process_ids;
    uint32_t signalled_handle_index;

    HandleTable::Entry<Event> socp_event;

    FakeSOC(FakeThread& thread);

    void ServiceThread( FakeThread& thread, const char* service_name, const uint32_t max_sessions,
                        decltype(ServiceHelper::SendReply) (*command_handler)(FakeThread&, FakeSOC&, std::string_view, uint32_t, const IPC::CommandHeader&));

    OS::Result ValidateSocket(uint32_t sockfd, ProcessId process_id);
};

OS::Result FakeSOC::ValidateSocket(uint32_t sockfd, ProcessId process_id) {
    auto context_found = contexts.find(process_id);
    if (context_found == contexts.end())
        return 0xD8E07006; // No context found

    auto socket_found = sockets.find(sockfd);
    if (socket_found == sockets.end())
        return 0xD8E07007; // Socket does not exist

    auto& socket = socket_found->second;
    if (socket.owner_process != process_id && !socket.is_global)
        return 0xC8A07004; // Not allowed to access socket

    return RESULT_OK;
}

static std::tuple<OS::Result> HandleInitializeSockets(FakeThread& thread, FakeSOC& context, uint32_t size, ProcessId process_id, Handle shared_mem) {
    auto pid_found = context.process_ids.find(context.signalled_handle_index);
    if (pid_found != context.process_ids.end())
        return std::make_tuple(0xC8A07004); // The process ID is already registered

    auto context_found = context.contexts.find(process_id);
    if (context_found != context.contexts.end())
        return std::make_tuple(0xC8A0700B); // A context is already registered

    if (context.process_ids.size() >= 32)
        return std::make_tuple(0xD860700A); // The process ID count limit has been reached

    context.contexts[process_id] = {.process_id = process_id};
    context.process_ids[context.signalled_handle_index] = process_id;
    return std::make_tuple(RESULT_OK);
}

static OS::ResultAnd<uint32_t> HandleSocket(FakeThread& thread, FakeSOC& context, uint32_t domain, uint32_t type, uint32_t protocol, ProcessId process_id) {
    auto context_found = context.contexts.find(process_id);
    if (context_found == context.contexts.end())
        return std::make_tuple(0xD8E07006, 0); // No context found

    auto& process_context = context_found->second;

    // The official sysmodule only allows IPv4 sockets
    const int native_domain = Domain3DSToNative(domain);
    if (native_domain != CTR_AF_INET)
        return std::make_tuple(RESULT_OK, -CTR_EAFNOSUPPORT);

    // The protocol must be chosen automatically
    const int native_protocol = SockProtocol3DSToNative(protocol);
    if (native_protocol != IPPROTO_IP)
        return std::make_tuple(RESULT_OK, -CTR_EPROTONOSUPPORT);

    // The official sysmodule has a limit of 64 sockets
    if (context.sockets.size() >= 64)
        return std::make_tuple(RESULT_OK, -CTR_EMFILE);

    const int native_type = SockType3DSToNative(type);
    if (native_type < 0)
        return std::make_tuple(RESULT_OK, -CTR_EPROTOTYPE);

    int ret = ::socket(native_domain, native_type, native_protocol);
    if (ret < 0) {
        ret = ErrorNativeTo3DS(errno);
    } else {
        Socket3DS socket = {.sockfd = ret, .owner_process = process_id};
        context.sockets.emplace(ret, socket);
        process_context.owned_sockets.emplace(ret, socket);
    }

    return std::make_tuple(RESULT_OK, ret);
}

static OS::ResultAnd<uint32_t> HandleListen(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t backlog, ProcessId process_id) {
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0);

    // The official sysmodule enforces a minimum backlog of 1
    if (static_cast<int>(backlog) < 1)
        backlog = 1;

    int ret = ::listen(sockfd, backlog);
    if (ret < 0)
        ret = ErrorNativeTo3DS(errno);
    return std::make_tuple(RESULT_OK, ret);
}

static OS::ResultAnd<uint32_t, IPC::StaticBuffer> HandleAccept(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t addrlen, ProcessId process_id) {
    const std::uint32_t size = std::min<uint32_t>(addrlen, sizeof(SockAddr3DS));
    IPC::StaticBuffer sock_buffer = { thread.ReadTLS(0x184), size, 0 };
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0, sock_buffer);

    // We have already verified that there is a process context
    auto& process_context = context.contexts[context.signalled_handle_index];

    // The official sysmodule has a limit of 64 sockets
    if (context.sockets.size() >= 64)
        return std::make_tuple(RESULT_OK, -CTR_EMFILE, sock_buffer);

    sockaddr_storage native_sockaddr{};
    socklen_t native_size = sizeof(native_sockaddr);
    int ret = ::accept(sockfd, reinterpret_cast<sockaddr*>(&native_sockaddr), &native_size);
    if (ret < 0)
        ret = ErrorNativeTo3DS(errno);
    SockAddr3DS sock_addr(native_sockaddr);
    char* sock_addr_ptr = reinterpret_cast<char*>(&sock_addr);
    for (uint32_t i = 0; i < size; i++) {
        thread.WriteMemory(sock_buffer.addr + i, *(sock_addr_ptr + i));
    }

    Socket3DS socket = {.sockfd = ret, .owner_process = process_id};
    context.sockets.emplace(ret, socket);
    process_context.owned_sockets.emplace(ret, socket);
    return std::make_tuple(RESULT_OK, ret, sock_buffer);
}

static OS::ResultAnd<uint32_t> HandleBind(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t addrlen, ProcessId process_id, IPC::StaticBuffer sock_addr_buffer) {
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0);

    SockAddr3DS sock_addr{};
    char* sock_addr_ptr = reinterpret_cast<char*>(&sock_addr);
    for (uint32_t i = 0; i < sock_addr_buffer.size; i++) {
        *sock_addr_ptr = thread.ReadMemory(sock_addr_buffer.addr + i);
        sock_addr_ptr++;
    }

    // Only IPv4 addresses are allowed
    if (sock_addr.sa_family != CTR_AF_INET || sock_addr.size < 0x8)
        return std::make_tuple(res, -CTR_EINVAL);

    sockaddr_storage native_sockaddr = sock_addr.ToNative();
    int ret = ::bind(sockfd, reinterpret_cast<sockaddr*>(&native_sockaddr), sizeof(native_sockaddr));
    if (ret < 0)
        ret = ErrorNativeTo3DS(errno);
    return std::make_tuple(RESULT_OK, ret);
}

static OS::ResultAnd<uint32_t> HandleConnect(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t addrlen, ProcessId process_id, IPC::StaticBuffer sock_addr_buffer) {
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0);

    SockAddr3DS sock_addr{};
    char* sock_addr_ptr = reinterpret_cast<char*>(&sock_addr);
    for (uint32_t i = 0; i < sock_addr_buffer.size; i++) {
        *sock_addr_ptr = thread.ReadMemory(sock_addr_buffer.addr + i);
        sock_addr_ptr++;
    }

    // Only IPv4 addresses are allowed
    if (sock_addr.sa_family != CTR_AF_INET || sock_addr.size < 0x8)
        return std::make_tuple(res, -CTR_EINVAL);

    sockaddr_storage native_sockaddr = sock_addr.ToNative();
    int ret = ::connect(sockfd, reinterpret_cast<sockaddr*>(&native_sockaddr), sizeof(native_sockaddr));
    if (ret < 0)
        ret = ErrorNativeTo3DS(errno);
    return std::make_tuple(RESULT_OK, ret);
}

static OS::ResultAnd<uint32_t, IPC::StaticBuffer, IPC::MappedBuffer> HandleRecvFromOther(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t len, uint32_t flags, uint32_t addrlen, ProcessId process_id, IPC::MappedBuffer recv_buffer) {
    uint32_t sock_size = std::min<size_t>(addrlen, sizeof(SockAddr3DS));
    IPC::StaticBuffer sock_buffer = { thread.ReadTLS(0x184), sock_size, 0 };
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0, sock_buffer, recv_buffer);

    // The original sysmodule does not allow flags larger than 0x4
    const int native_flags = SendRecvFlags3DSToNative(flags);
    if (flags & ~CTR_FLAGS_ALL)
        return std::make_tuple(RESULT_OK, -CTR_EOPNOTSUPP, sock_buffer, recv_buffer);

    std::vector<uint8_t> buffer;
    buffer.resize(len);
    sockaddr_storage native_sockaddr{};
    socklen_t addr_size = sizeof(native_sockaddr);

    // Blocking sockets would block the entire emulator. To avoid this, we
    // run the operation asyncronously and wait until it finishes
    struct RecvFromOtherDetails {
        uint32_t sockfd;
        std::vector<uint8_t>* buffer;
        int native_flags;
        sockaddr_storage* native_sockaddr;
        socklen_t* addr_size;
    };
    RecvFromOtherDetails recvfrom_other_details = {.sockfd = sockfd, .buffer = &buffer, .native_flags = native_flags, .native_sockaddr = &native_sockaddr, .addr_size = &addr_size};
    auto future = std::async(std::launch::async, [recvfrom_other_details]() {
        const int ret = ::recvfrom(recvfrom_other_details.sockfd, recvfrom_other_details.buffer->data(), recvfrom_other_details.buffer->size(), recvfrom_other_details.native_flags, reinterpret_cast<sockaddr*>(recvfrom_other_details.native_sockaddr), recvfrom_other_details.addr_size);
        if (ret < 0) {
            return -errno; // errno isn't preserved between threads so we return it here
        }

        return ret;
    });

    // To avoid blocking the emulator, we check the future status among a small period of
    // time (100 ns). If it isn't ready, we put the thread to sleep to let other threads continue
    while (future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        thread.CallSVC(&OS::SVCSleepThread, 100);
    }

    int ret = future.get();
    if (ret < 0)
        ret = ErrorNativeTo3DS(-ret);

    SockAddr3DS sock_addr(native_sockaddr);
    char* sock_addr_ptr = reinterpret_cast<char*>(&sock_addr);
    for (uint32_t i = 0; i < len; i++) {
        thread.WriteMemory(recv_buffer.addr + i, *(buffer.data() + i));
    }
    for (uint32_t i = 0; i < sock_size; i++) {
        thread.WriteMemory(sock_buffer.addr + i, *(sock_addr_ptr + i));
    }
    return std::make_tuple(RESULT_OK, ret, sock_buffer, recv_buffer);
}

static OS::ResultAnd<uint32_t, uint32_t, IPC::StaticBuffer, IPC::StaticBuffer> HandleRecvFrom(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t len, uint32_t flags, uint32_t addrlen, ProcessId process_id) {
    // The official sysmodule limits the buffer size of this command to 0x2000 bytes
    uint32_t size = std::min<size_t>(0x2000, len);
    uint32_t sock_size = std::min<size_t>(addrlen, sizeof(SockAddr3DS));
    IPC::StaticBuffer recv_buffer = { thread.ReadTLS(0x184), size, 0 };
    IPC::StaticBuffer sock_buffer = { thread.ReadTLS(0x18C), sock_size, 1 };
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0, 0, recv_buffer, sock_buffer);

    // The original sysmodule does not allow flags larger than 0x4
    const int native_flags = SendRecvFlags3DSToNative(flags);
    if (flags & ~CTR_FLAGS_ALL)
        return std::make_tuple(RESULT_OK, -CTR_EOPNOTSUPP, 0, recv_buffer, sock_buffer);

    std::vector<uint8_t> buffer;
    buffer.resize(size);
    sockaddr_storage native_sockaddr{};
    socklen_t addr_size = sizeof(native_sockaddr);

    // Blocking sockets would block the entire emulator. To avoid this, we
    // run the operation asyncronously and wait until it finishes
    struct RecvFromDetails {
        uint32_t sockfd;
        std::vector<uint8_t>* buffer;
        int native_flags;
        sockaddr_storage* native_sockaddr;
        socklen_t* addr_size;
    };
    RecvFromDetails recvfrom_details = {.sockfd = sockfd, .buffer = &buffer, .native_flags = native_flags, .native_sockaddr = &native_sockaddr, .addr_size = &addr_size};
    auto future = std::async(std::launch::async, [recvfrom_details]() {
        const int ret = ::recvfrom(recvfrom_details.sockfd, recvfrom_details.buffer->data(), recvfrom_details.buffer->size(), recvfrom_details.native_flags, reinterpret_cast<sockaddr*>(recvfrom_details.native_sockaddr), recvfrom_details.addr_size);
        if (ret < 0) {
            return -errno; // errno isn't preserved between threads so we return it here
        }

        return ret;
    });

    // To avoid blocking the emulator, we check the future status among a small period of
    // time (100 ns). If it isn't ready, we put the thread to sleep to let other threads continue
    while (future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        thread.CallSVC(&OS::SVCSleepThread, 100);
    }

    int ret = future.get();
    int read = 0;
    if (ret < 0) {
        ret = ErrorNativeTo3DS(-ret);
    } else {
        read = ret;
    }
    SockAddr3DS sock_addr(native_sockaddr);

    char* sock_addr_ptr = reinterpret_cast<char*>(&sock_addr);
    for (uint32_t i = 0; i < size; i++) {
        thread.WriteMemory(recv_buffer.addr + i, *(buffer.data() + i));
    }
    for (uint32_t i = 0; i < sock_size; i++) {
        thread.WriteMemory(sock_buffer.addr + i, *(sock_addr_ptr + i));
    }
    return std::make_tuple(RESULT_OK, ret, read, recv_buffer, sock_buffer);
}

static OS::ResultAnd<uint32_t, IPC::MappedBuffer> HandleSendToOther(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t len, uint32_t flags, uint32_t addrlen, ProcessId process_id, IPC::StaticBuffer sock_addr_buffer, IPC::MappedBuffer data_buffer) {
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0, data_buffer);

    // The original sysmodule does not allow flags larger than 0x4
    const int native_flags = SendRecvFlags3DSToNative(flags);
    if (flags & ~CTR_FLAGS_ALL)
        return std::make_tuple(RESULT_OK, -CTR_EOPNOTSUPP, data_buffer);

    std::vector<uint8_t> buffer;
    buffer.resize(len);
    for (uint32_t i = 0; i < len; i++) {
        *(buffer.data() + i) = thread.ReadMemory(data_buffer.addr + i);
    }
    SockAddr3DS sock_addr{};
    char* sock_addr_ptr = reinterpret_cast<char*>(&sock_addr);
    for (uint32_t i = 0; i < sock_addr_buffer.size; i++) {
        *sock_addr_ptr = thread.ReadMemory(sock_addr_buffer.addr + i);
        sock_addr_ptr++;
    }
    sockaddr_storage native_sockaddr = sock_addr.ToNative();

    // Blocking sockets would block the entire emulator. To avoid this, we
    // run the operation asyncronously and wait until it finishes
    struct SendToOtherDetails {
        uint32_t sockfd;
        std::vector<uint8_t>* buffer;
        int native_flags;
        sockaddr_storage* native_sockaddr;
        socklen_t* addr_size;
    };
    SendToOtherDetails sendto_other_details = {.sockfd = sockfd, .buffer = &buffer, .native_flags = native_flags, .native_sockaddr = &native_sockaddr};
    auto future = std::async(std::launch::async, [sendto_other_details]() {
        const int ret = ::sendto(sendto_other_details.sockfd, sendto_other_details.buffer->data(), sendto_other_details.buffer->size(), sendto_other_details.native_flags, reinterpret_cast<sockaddr*>(sendto_other_details.native_sockaddr), sizeof(*sendto_other_details.native_sockaddr));
        if (ret < 0) {
            return -errno; // errno isn't preserved between threads so we return it here
        }

        return ret;
    });

    // To avoid blocking the emulator, we check the future status among a small period of
    // time (100 ns). If it isn't ready, we put the thread to sleep to let other threads continue
    while (future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        thread.CallSVC(&OS::SVCSleepThread, 100);
    }

    int ret = future.get();
    if (ret < 0)
        ret = ErrorNativeTo3DS(-ret);
    return std::make_tuple(RESULT_OK, ret, data_buffer);
}

static OS::ResultAnd<uint32_t> HandleSendTo(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t len, uint32_t flags, uint32_t addrlen, ProcessId process_id, IPC::StaticBuffer data_buffer, IPC::StaticBuffer sock_addr_buffer) {
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0);

    // The original sysmodule does not allow flags larger than 0x4
    const int native_flags = SendRecvFlags3DSToNative(flags);
    if (flags & ~CTR_FLAGS_ALL)
        return std::make_tuple(RESULT_OK, -CTR_EOPNOTSUPP);

    std::vector<uint8_t> buffer;
    buffer.resize(len);
    for (uint32_t i = 0; i < len; i++) {
        *(buffer.data() + i) = thread.ReadMemory(data_buffer.addr + i);
    }
    SockAddr3DS sock_addr{};
    char* sock_addr_ptr = reinterpret_cast<char*>(&sock_addr);
    for (uint32_t i = 0; i < sock_addr_buffer.size; i++) {
        *sock_addr_ptr = thread.ReadMemory(sock_addr_buffer.addr + i);
        sock_addr_ptr++;
    }
    sockaddr_storage native_sockaddr = sock_addr.ToNative();

    // Blocking sockets would block the entire emulator. To avoid this, we
    // run the operation asyncronously and wait until it finishes
    struct SendToDetails {
        uint32_t sockfd;
        std::vector<uint8_t>* buffer;
        int native_flags;
        sockaddr_storage* native_sockaddr;
        socklen_t* addr_size;
    };
    SendToDetails sendto_details = {.sockfd = sockfd, .buffer = &buffer, .native_flags = native_flags, .native_sockaddr = &native_sockaddr};
    auto future = std::async(std::launch::async, [sendto_details]() {
        const int ret = ::sendto(sendto_details.sockfd, sendto_details.buffer->data(), sendto_details.buffer->size(), sendto_details.native_flags, reinterpret_cast<sockaddr*>(sendto_details.native_sockaddr), sizeof(*sendto_details.native_sockaddr));
        if (ret < 0) {
            return -errno; // errno isn't preserved between threads so we return it here
        }

        return ret;
    });

    // To avoid blocking the emulator, we check the future status among a small period of
    // time (100 ns). If it isn't ready, we put the thread to sleep to let other threads continue
    while (future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        thread.CallSVC(&OS::SVCSleepThread, 100);
    }

    int ret = future.get();
    if (ret < 0)
        ret = ErrorNativeTo3DS(-ret);
    return std::make_tuple(RESULT_OK, ret);
}

static OS::ResultAnd<uint32_t> HandleClose(FakeThread& thread, FakeSOC& context, uint32_t sockfd, ProcessId process_id) {
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0);

    int ret = ::close(sockfd);
    if (ret < 0) {
        ret = ErrorNativeTo3DS(errno);
    } else {
        context.contexts[process_id].owned_sockets.erase(sockfd);
        context.sockets.erase(sockfd);
    }

    return std::make_tuple(RESULT_OK, ret);
}

static OS::ResultAnd<uint32_t> HandleShutdown(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t how, ProcessId process_id) {
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0);

    const int native_how = ShutdownHow3DSToNative(how);
    if (native_how < 0)
        return std::make_tuple(RESULT_OK, -CTR_EINVAL);

    int ret = ::shutdown(sockfd, native_how);
    if (ret < 0)
        ret = ErrorNativeTo3DS(errno);

    return std::make_tuple(RESULT_OK, ret);
}

static OS::ResultAnd<uint32_t, IPC::StaticBuffer> HandleGetHostByName(FakeThread& thread, FakeSOC& context, uint32_t name_size, uint32_t out_size, IPC::StaticBuffer name_buffer) {
    IPC::StaticBuffer out_buffer = { thread.ReadTLS(0x184), sizeof(Hostent3DS), 0 };
    if (name_size >= 256 || out_size < sizeof(Hostent3DS))
        return std::make_tuple(0xD8E073EC, 0, out_buffer); // Invalid size

    std::string name;
    name.resize(256);
    for (uint32_t i = 0; i < name_size; i++) {
        *(name.data() + i) = thread.ReadMemory(name_buffer.addr + i);
    }

    const hostent* native_host = ::gethostbyname(name.c_str());
    if (native_host == nullptr) {
        // The POSIX result is always -1 if something fails here
        return std::make_tuple(RESULT_OK, -1, out_buffer);
    }

    const Hostent3DS host(native_host);
    const char* host_ptr = reinterpret_cast<const char*>(&host);
    for (uint32_t i = 0; i < sizeof(Hostent3DS); i++) {
        thread.WriteMemory(out_buffer.addr + i, *(host_ptr + i));
    }

    return std::make_tuple(RESULT_OK, 0, out_buffer);
}

static OS::ResultAnd<uint32_t, IPC::StaticBuffer> HandleGetHostByAddr(FakeThread& thread, FakeSOC& context, uint32_t addr_size, uint32_t type, uint32_t out_size, IPC::StaticBuffer addr_buffer) {
    IPC::StaticBuffer out_buffer = { thread.ReadTLS(0x184), sizeof(Hostent3DS), 0 };
    if (out_size < sizeof(Hostent3DS))
        return std::make_tuple(0xD8E073EC, 0, out_buffer); // Invalid size

    const int native_type = Domain3DSToNative(type);

    if (!(native_type == AF_INET && addr_size == sizeof(in_addr)) && !(native_type == AF_INET6 && addr_size == sizeof(in6_addr))) {
        // The POSIX result is always -1 if something fails here
        return std::make_tuple(RESULT_OK, -1, out_buffer);
    }

    in_addr addr;
    char* addr_ptr = reinterpret_cast<char*>(&addr);
    for (uint32_t i = 0; i < addr_size; i++) {
        *addr_ptr = thread.ReadMemory(addr_buffer.addr + i);
        addr_ptr++;
    }

    const hostent* native_host = ::gethostbyaddr(&addr, addr_size, native_type);
    if (native_host == nullptr) {
        // The POSIX result is always -1 if something fails here
        return std::make_tuple(RESULT_OK, -1, out_buffer);
    }

    const Hostent3DS host(native_host);
    const char* host_ptr = reinterpret_cast<const char*>(&host);
    for (uint32_t i = 0; i < sizeof(Hostent3DS); i++) {
        thread.WriteMemory(out_buffer.addr + i, *(host_ptr + i));
    }

    return std::make_tuple(RESULT_OK, 0, out_buffer);
}

static OS::ResultAnd<uint32_t, uint32_t, IPC::StaticBuffer> HandleGetAddrInfo(FakeThread& thread, FakeSOC& context, uint32_t node_size, uint32_t service_size, uint32_t hints_size, uint32_t out_size, IPC::StaticBuffer node_buffer, IPC::StaticBuffer service_buffer, IPC::StaticBuffer hints_buffer) {
    uint32_t info_size = std::min<size_t>(out_size, sizeof(AddrInfo3DS) * 24);
    IPC::StaticBuffer info_buffer = { thread.ReadTLS(0x184), info_size, 0 };
    std::string node;
    if (node_size > 0) {
        node.resize(node_size);
        for (uint32_t i = 0; i < node_size; i++) {
            *(node.data() + i) = thread.ReadMemory(node_buffer.addr + i);
        }
    }

    std::string service;
    if (service_size > 0) {
        service.resize(service_size);
        for (uint32_t i = 0; i < service_size; i++) {
            *(service.data() + i) = thread.ReadMemory(service_buffer.addr + i);
        }
    }

    AddrInfo3DS hints{};
    char* hints_ptr = reinterpret_cast<char*>(&hints);
    for (uint32_t i = 0; i < hints_size; i++) {
        *(hints_ptr + i) = thread.ReadMemory(hints_buffer.addr + i);
    }

    // If either the protocol or the socket type is missing, assign its value from the other one
    if (hints.ai_protocol != 0 && hints.ai_socktype == 0) {
        if (hints.ai_protocol == CTR_IPPROTO_TCP) {
            hints.ai_socktype = CTR_SOCK_STREAM;
        } else {
            hints.ai_socktype = CTR_SOCK_DGRAM;
        }
    }
    if (hints.ai_socktype != 0 && hints.ai_protocol == 0) {
        if (hints.ai_socktype == CTR_SOCK_STREAM) {
            hints.ai_protocol = CTR_IPPROTO_TCP;
        } else {
            hints.ai_protocol = CTR_IPPROTO_UDP;
        }
    }

    auto native_hints = hints.ToNative();
    addrinfo* native_infos = nullptr;
    int ret = ::getaddrinfo(node.c_str(), service.c_str(), &native_hints, &native_infos);
    if (ret < 0) {
        ret = AddrInfoErrorNativeTo3DS(ret);
        return std::make_tuple(RESULT_OK, ret, 0, info_buffer);
    }

    uint32_t count = 0;
    if (native_infos != nullptr) {
        std::vector<AddrInfo3DS> infos;
        addrinfo* next_info = native_infos;
        while (next_info != nullptr) {
            addrinfo* current_info = next_info;
            AddrInfo3DS info(*current_info);
            infos.emplace_back(info);
            next_info = current_info->ai_next;
        }
        freeaddrinfo(native_infos);

        count = infos.size();
        char* infos_ptr = reinterpret_cast<char*>(infos.data());
        for (uint32_t i = 0; i < info_size; i++) {
            thread.WriteMemory(info_buffer.addr + i, *(infos_ptr + i));
        }
    }

    return std::make_tuple(RESULT_OK, ret, count, info_buffer);
}

static OS::ResultAnd<uint32_t, IPC::StaticBuffer, IPC::StaticBuffer> HandleGetNameInfo(FakeThread& thread, FakeSOC& context, uint32_t addrlen, uint32_t host_size, uint32_t serv_size, uint32_t flags, IPC::StaticBuffer sock_addr_buffer) {
    uint32_t host_buffer_size = std::min<uint32_t>(host_size, 256);
    uint32_t serv_buffer_size = std::min<uint32_t>(serv_size, 256);
    IPC::StaticBuffer host_buffer = { thread.ReadTLS(0x184), host_buffer_size, 0 };
    IPC::StaticBuffer serv_buffer = { thread.ReadTLS(0x18C), serv_buffer_size, 1 };

    if (addrlen < sizeof(SockAddr3DS))
        return std::make_tuple(0xD8E073EC, 0, host_buffer, serv_buffer); // Invalid size

    SockAddr3DS sock_addr{};
    char* sock_addr_ptr = reinterpret_cast<char*>(&sock_addr);
    for (uint32_t i = 0; i < sock_addr_buffer.size; i++) {
        *sock_addr_ptr = thread.ReadMemory(sock_addr_buffer.addr + i);
        sock_addr_ptr++;
    }
    sockaddr_storage native_sockaddr = sock_addr.ToNative();

    std::string host;
    host.resize(host_buffer_size);

    std::string serv;
    serv.resize(serv_buffer_size);

    const int native_flags = NameInfoFlags3DSToNative(flags);

    int ret = ::getnameinfo(reinterpret_cast<sockaddr*>(&native_sockaddr), sizeof(native_sockaddr), host.data(), host_buffer_size, serv.data(), serv_buffer_size, native_flags);
    if (ret < 0) {
        ret = AddrInfoErrorNativeTo3DS(ret);
        return std::make_tuple(RESULT_OK, ret, host_buffer, serv_buffer);
    }

    const char* host_ptr = host.c_str();
    for (uint32_t i = 0; i < host_buffer_size; i++) {
        thread.WriteMemory(host_buffer.addr + i, *(host_ptr + i));
    }

    const char* serv_ptr = serv.c_str();
    for (uint32_t i = 0; i < serv_buffer_size; i++) {
        thread.WriteMemory(serv_buffer.addr + i, *(serv_ptr + i));
    }

    return std::make_tuple(RESULT_OK, ret, host_buffer, serv_buffer);
}

static OS::ResultAnd<uint32_t, uint32_t, IPC::StaticBuffer> HandleGetSockOpt(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t level, uint32_t optname, uint32_t optlen, ProcessId process_id) {
    uint32_t optval_buffer_size = std::min<uint32_t>(optlen, 0x2000);
    IPC::StaticBuffer optval_buffer = { thread.ReadTLS(0x184), optval_buffer_size, 0 };

    if (level == CTR_SOL_SOCKET && optname == CTR_SO_LINGER) {
        if (optval_buffer_size < sizeof(Linger3DS))
            return std::make_tuple(RESULT_OK, -CTR_EINVAL, 0, optval_buffer);

        optval_buffer_size = sizeof(linger);
    }

    std::vector<uint8_t> optval;
    optval.resize(optval_buffer_size);

    int native_level, native_optname;
    std::tie(native_level, native_optname) = SockOpt3DSToNative(level, optname);

    int ret = ::getsockopt(sockfd, native_level, native_optname, optval.data(), &optval_buffer_size);
    if (ret < 0) {
        ret = ErrorNativeTo3DS(errno);
        return std::make_tuple(RESULT_OK, ret, 0, optval_buffer);
    }

    if (level == CTR_SOL_SOCKET && optname == CTR_SO_LINGER) {
        linger linger_native{};
        std::memcpy(&linger_native, optval.data(), sizeof(linger));
        Linger3DS l(linger_native);
        std::memcpy(optval.data(), &l, sizeof(Linger3DS));

        optval_buffer_size = sizeof(Linger3DS);
    }

    char* optval_ptr = reinterpret_cast<char*>(optval.data());
    for (uint32_t i = 0; i < optval_buffer_size; i++) {
        thread.WriteMemory(optval_buffer.addr + i, *(optval_ptr + i));
    }

    return std::make_tuple(RESULT_OK, ret, optval_buffer_size, optval_buffer);
}

static OS::ResultAnd<uint32_t> HandleSetSockOpt(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t level, uint32_t optname, uint32_t optlen, ProcessId process_id, IPC::StaticBuffer optval_buffer) {
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0);

    std::vector<uint8_t> optval;
    optval.resize(optlen);
    for (uint32_t i = 0; i < optval_buffer.size; i++) {
        *(optval.data() + i) = thread.ReadMemory(optval_buffer.addr + i);
    }

    // All fields have a minimum size of 4
    if (optlen < 4)
        return std::make_tuple(res, -CTR_EINVAL);

    if (level == CTR_SOL_SOCKET && optname == CTR_SO_LINGER) {
        if (optlen < sizeof(Linger3DS))
            return std::make_tuple(res, -CTR_EINVAL);

        Linger3DS linger{};
        std::memcpy(&linger, optval.data(), sizeof(Linger3DS));
        auto linger_native = linger.ToNative();
        std::memcpy(optval.data(), &linger_native, sizeof(linger));
    }

    int native_level, native_optname;
    std::tie(native_level, native_optname) = SockOpt3DSToNative(level, optname);

    int ret = ::setsockopt(sockfd, native_level, native_optname, optval.data(), optlen);
    if (ret < 0)
        ret = ErrorNativeTo3DS(errno);

    return std::make_tuple(RESULT_OK, ret);
}

static OS::ResultAnd<uint32_t> HandleFcntl(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t cmd, uint32_t arg, ProcessId process_id) {
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0);

    // Only F_GETFL and F_SETFL are allowed
    const int native_cmd = FcntlCmd3DSToNative(cmd);
    if (native_cmd < 0)
        return std::make_tuple(RESULT_OK, -CTR_EINVAL);

    // Translate O_NONBLOCK argument. TODO - Are there any more args?
    if (native_cmd == F_SETFL && arg & CTR_O_NONBLOCK) {
        arg = O_NONBLOCK;
    } else {
        arg = 0; // Clear the argument for safety
    }

    int ret = ::fcntl(sockfd, native_cmd, arg);
    if (ret < 0)
        ret = ErrorNativeTo3DS(errno);
    if (native_cmd == F_GETFL && ret & O_NONBLOCK)
        ret = CTR_O_NONBLOCK;

    return std::make_tuple(RESULT_OK, ret);
}

static OS::ResultAnd<uint32_t, IPC::StaticBuffer> HandlePoll(FakeThread& thread, FakeSOC& context, uint32_t nfds, uint32_t timeout, ProcessId process_id, IPC::StaticBuffer pollfds_buffer) {
    // The original sysmodule uses a maximum of 64 sockets
    uint32_t pollfds_out_size = std::min(sizeof(PollFd3DS) * nfds, sizeof(PollFd3DS) * 64);
    IPC::StaticBuffer pollfds_out_buffer = { thread.ReadTLS(0x184), pollfds_out_size, 0 };

    if (nfds >= 64)
        return std::make_tuple(RESULT_OK, -CTR_EINVAL, pollfds_out_buffer);

    std::vector<PollFd3DS> pollfds;
    pollfds.resize(nfds);
    char* pollfds_ptr = reinterpret_cast<char*>(pollfds.data());
    for (uint32_t i = 0; i < pollfds_out_size; i++) {
        *pollfds_ptr = thread.ReadMemory(pollfds_buffer.addr + i);
        pollfds_ptr++;
    }

    std::vector<pollfd> native_pollfds;
    std::vector<bool> low_write_priorities;
    for (auto pollfd : pollfds) {
        bool low_write_priority = false;
        native_pollfds.emplace_back(pollfd.ToNative(low_write_priority));
        low_write_priorities.emplace_back(low_write_priority);
    }

    int ret = ::poll(native_pollfds.data(), nfds, timeout);
    if (ret < 0) {
        ret = ErrorNativeTo3DS(errno);
        return std::make_tuple(RESULT_OK, ret, pollfds_out_buffer);
    }

    std::vector<PollFd3DS> pollfds_out;
    for (size_t i = 0; i < native_pollfds.size(); i++) {
        const auto pollfd = native_pollfds[i];
        const auto low_write_priority = low_write_priorities[i];
        pollfds_out.emplace_back(PollFd3DS(pollfd, low_write_priority));
    }

    char* pollfds_out_ptr = reinterpret_cast<char*>(pollfds_out.data());
    for (uint32_t i = 0; i < pollfds_out_size; i++) {
        thread.WriteMemory(pollfds_out_buffer.addr + i, *(pollfds_out_ptr + i));
    }

    return std::make_tuple(RESULT_OK, ret, pollfds_out_buffer);
}

static OS::ResultAnd<uint32_t> HandleSockAtMark(FakeThread& thread, FakeSOC& context, uint32_t sockfd, ProcessId process_id) {
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0);

    int ret = ::sockatmark(sockfd);
    if (ret < 0)
        ret = ErrorNativeTo3DS(errno);

    return std::make_tuple(RESULT_OK, ret);
}

static OS::ResultAnd<uint32_t> HandleGetHostId(FakeThread& thread, FakeSOC& context) {
    // The gethostid function doesn't return the IP address on a standard way,
    // so we workaround it by converting the hostname to the address
    //
    // NOTE: The official sysmodule returns zero when an error happens
    std::string hostname;
    hostname.resize(256);
    int ret = ::gethostname(hostname.data(), hostname.size());
    if (ret < 0)
        return std::make_tuple(RESULT_OK, 0);
    auto host_entry = ::gethostbyname(hostname.data());
    if (host_entry == nullptr)
        return std::make_tuple(RESULT_OK, 0);
    if (host_entry->h_addr_list == nullptr)
        return std::make_tuple(RESULT_OK, 0);

    auto host_address = reinterpret_cast<in_addr*>(host_entry->h_addr_list[0]);
    if (host_address == nullptr)
        return std::make_tuple(RESULT_OK, 0);

    return std::make_tuple(RESULT_OK, host_address->s_addr);
}

static OS::ResultAnd<uint32_t, IPC::StaticBuffer> HandleGetSockName(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t addrlen, ProcessId process_id) {
    const std::uint32_t size = std::min<uint32_t>(addrlen, sizeof(SockAddr3DS));
    IPC::StaticBuffer sock_buffer = { thread.ReadTLS(0x184), size, 0 };
    // Unlike other commands, this one doesn't check the socket ownership
    auto socket_found = context.sockets.find(sockfd);
    if (socket_found == context.sockets.end())
        return std::make_tuple(RESULT_OK, -CTR_EBADF, sock_buffer);

    sockaddr_storage native_sockaddr{};
    socklen_t native_size = sizeof(native_sockaddr);
    int ret = ::getsockname(sockfd, reinterpret_cast<sockaddr*>(&native_sockaddr), &native_size);
    if (ret < 0)
        ret = ErrorNativeTo3DS(errno);

    SockAddr3DS sock_addr(native_sockaddr);

    char* sock_addr_ptr = reinterpret_cast<char*>(&sock_addr);
    for (uint32_t i = 0; i < size; i++) {
        thread.WriteMemory(sock_buffer.addr + i, *(sock_addr_ptr + i));
    }
    return std::make_tuple(RESULT_OK, ret, sock_buffer);
}

static OS::ResultAnd<uint32_t, IPC::StaticBuffer> HandleGetPeerName(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t addrlen, ProcessId process_id) {
    const std::uint32_t size = std::min<uint32_t>(addrlen, sizeof(SockAddr3DS));
    IPC::StaticBuffer sock_buffer = { thread.ReadTLS(0x184), size, 0 };
    // Unlike other commands, this one doesn't check the socket ownership
    auto socket_found = context.sockets.find(sockfd);
    if (socket_found == context.sockets.end())
        return std::make_tuple(RESULT_OK, -CTR_EBADF, sock_buffer);

    sockaddr_storage native_sockaddr{};
    socklen_t native_size = sizeof(native_sockaddr);
    int ret = ::getpeername(sockfd, reinterpret_cast<sockaddr*>(&native_sockaddr), &native_size);
    if (ret < 0)
        ret = ErrorNativeTo3DS(errno);

    SockAddr3DS sock_addr(native_sockaddr);

    char* sock_addr_ptr = reinterpret_cast<char*>(&sock_addr);
    for (uint32_t i = 0; i < size; i++) {
        thread.WriteMemory(sock_buffer.addr + i, *(sock_addr_ptr + i));
    }
    return std::make_tuple(RESULT_OK, ret, sock_buffer);
}

static std::tuple<OS::Result> HandleShutdownSockets(FakeThread& thread, FakeSOC& context) {
    // Cleanup the process ID, the context and the owned sockets
    auto pid_found = context.process_ids.find(context.signalled_handle_index);
    if (pid_found != context.process_ids.end()) {
        auto context_found = context.contexts.find(pid_found->second);
        if (context_found != context.contexts.end()) {
            auto& process_context = context_found->second;
            for (auto& socket : process_context.owned_sockets) {
                ::close(socket.first);
                context.sockets.erase(socket.first);
            }

            process_context.owned_sockets.clear();
            context.contexts.erase(context_found->first);
        }

        context.process_ids.erase(pid_found->first);
    }

    return std::make_tuple(RESULT_OK);
}

static OS::ResultAnd<uint32_t, uint32_t, IPC::StaticBuffer> HandleGetNetworkOpt(FakeThread& thread, FakeSOC& context, uint32_t level, uint32_t optname, uint32_t optlen) {
    uint32_t optval_buffer_size = std::min<uint32_t>(optlen, 0x2000);
    IPC::StaticBuffer optval_buffer = { thread.ReadTLS(0x184), optval_buffer_size, 0 };

    std::vector<uint8_t> optval;
    optval.resize(optval_buffer_size);

    // Only CTR_SOL_CONFIG is allowed
    if (level != CTR_SOL_CONFIG)
        return std::make_tuple(RESULT_OK, -CTR_ENOPROTOOPT, 0, optval_buffer);

    switch (optname) {
    case NETOPT_MAC_ADDRESS: {
        if (optval_buffer_size < 6)
            return std::make_tuple(RESULT_OK, -CTR_EINVAL, 0, optval_buffer);

        // Stubbed for now
        std::array<uint8_t, 6> stub_mac{};
        memcpy(optval.data(), stub_mac.data(), stub_mac.size());
        break;
    }
    case NETOPT_IP_INFO: {
        if (optval_buffer_size < sizeof(SocketIPInfo))
            return std::make_tuple(RESULT_OK, -CTR_EINVAL, 0, optval_buffer);

        SocketIPInfo info{};
        ifaddrs* addrs;
        int ret = ::getifaddrs(&addrs);
        if (ret == 0) {
            // Select the first IPv4 interface which isn't a loopback
            for (ifaddrs* this_addr = addrs; this_addr != nullptr; this_addr = this_addr->ifa_next) {
                if (this_addr->ifa_flags & IFF_LOOPBACK || this_addr->ifa_addr == nullptr || this_addr->ifa_addr->sa_family != AF_INET)
                    continue;

                info.ip = reinterpret_cast<sockaddr_in*>(this_addr->ifa_addr)->sin_addr;
                info.netmask = reinterpret_cast<sockaddr_in*>(this_addr->ifa_netmask)->sin_addr;
                info.broadcast = reinterpret_cast<sockaddr_in*>(this_addr->ifa_broadaddr)->sin_addr;
                break;
            }

            ::freeifaddrs(addrs);
        }

        memcpy(optval.data(), &info, sizeof(SocketIPInfo));
        break;
    }
    default:
        throw Mikage::Exceptions::NotImplemented("GetNetworkOpt optname 0x{:#x} not implemented", optname);
    }

    char* optval_ptr = reinterpret_cast<char*>(optval.data());
    for (uint32_t i = 0; i < optval_buffer_size; i++) {
        thread.WriteMemory(optval_buffer.addr + i, *(optval_ptr + i));
    }

    return std::make_tuple(RESULT_OK, 0, optval_buffer_size, optval_buffer);
}

static OS::ResultAnd<uint32_t> HandleSendToMultiple(FakeThread& thread, FakeSOC& context, uint32_t sockfd, uint32_t len, uint32_t flags, uint32_t addrlen, uint32_t socks_size, ProcessId process_id, IPC::StaticBuffer data_buffer, IPC::StaticBuffer sock_addr_buffer) {
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res, 0);

    const uint32_t sock_addr_count = socks_size / addrlen;
    if (sock_addr_count < 1)
        return std::make_tuple(0xD8E073EC, 0); // Invalid size

    // The original sysmodule does not allow flags larger than 0x4
    const int native_flags = SendRecvFlags3DSToNative(flags);
    if (flags & ~CTR_FLAGS_ALL)
        return std::make_tuple(RESULT_OK, -CTR_EOPNOTSUPP);

    std::vector<uint8_t> buffer;
    buffer.resize(len);
    for (uint32_t i = 0; i < len; i++) {
        *(buffer.data() + i) = thread.ReadMemory(data_buffer.addr + i);
    }

    std::vector<SockAddr3DS> sock_addrs;
    sock_addrs.resize(sock_addr_count);
    char* sock_addr_ptr = reinterpret_cast<char*>(sock_addrs.data());
    for (uint32_t i = 0; i < sock_addr_buffer.size; i++) {
        *sock_addr_ptr = thread.ReadMemory(sock_addr_buffer.addr + i);
        sock_addr_ptr++;
    }

    std::vector<sockaddr_storage> native_sockaddrs;
    for (SockAddr3DS& sock_addr : sock_addrs) {
        native_sockaddrs.push_back(sock_addr.ToNative());
    }

    // Blocking sockets would block the entire emulator. To avoid this, we
    // run the operation asyncronously and wait until it finishes
    struct SendToMultipleDetails {
        uint32_t sockfd;
        std::vector<uint8_t>* buffer;
        int native_flags;
        std::vector<sockaddr_storage>* native_sockaddrs;
        socklen_t* addr_size;
    };
    SendToMultipleDetails sendtomultiple_details = {.sockfd = sockfd, .buffer = &buffer, .native_flags = native_flags, .native_sockaddrs = &native_sockaddrs};
    auto future = std::async(std::launch::async, [sendtomultiple_details]() {
        int ret = 0;
        for (auto& native_sockaddr : *sendtomultiple_details.native_sockaddrs) {
            const int ret = ::sendto(sendtomultiple_details.sockfd, sendtomultiple_details.buffer->data(), sendtomultiple_details.buffer->size(), sendtomultiple_details.native_flags, reinterpret_cast<sockaddr*>(&native_sockaddr), sizeof(native_sockaddr));

            // If any of the calls fail, error immediately
            if (ret < 0) {
                return -errno; // errno isn't preserved between threads so we return it here
            }
        }

        return ret;
    });

    // To avoid blocking the emulator, we check the future status among a small period of
    // time (100 ns). If it isn't ready, we put the thread to sleep to let other threads continue
    while (future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        thread.CallSVC(&OS::SVCSleepThread, 100);
    }

    int ret = future.get();
    if (ret < 0)
        ret = ErrorNativeTo3DS(-ret);
    return std::make_tuple(RESULT_OK, ret);
}

static std::tuple<OS::Result> HandleCloseSockets(FakeThread& thread, FakeSOC& context, ProcessId process_id) {
    // Only cleanup the sockets of the process ID
    auto context_found = context.contexts.find(process_id);
    if (context_found != context.contexts.end()) {
        auto& process_context = context_found->second;
        for (auto& socket : process_context.owned_sockets) {
            ::close(socket.first);
            context.sockets.erase(socket.first);
        }

        process_context.owned_sockets.clear();
    }

    return std::make_tuple(RESULT_OK);
}

static std::tuple<OS::Result> HandleAddGlobalSocket(FakeThread& thread, FakeSOC& context, uint32_t sockfd) {
    auto process_id_found = context.process_ids.find(context.signalled_handle_index);
    if (process_id_found == context.process_ids.end())
        return std::make_tuple(0xD8E07006);

    ProcessId process_id = process_id_found->second;
    OS::Result res = context.ValidateSocket(sockfd, process_id);
    if (res < 0)
        return std::make_tuple(res);

    context.sockets[sockfd].is_global = true;

    return std::make_tuple(RESULT_OK);
}

static decltype(ServiceHelper::SendReply) SOCUCommandHandler(FakeThread& thread, FakeSOC& context, std::string_view service_name, uint32_t signalled_handle_index, const IPC::CommandHeader& header) {
    context.signalled_handle_index = signalled_handle_index;
    using namespace Platform::SOC;
    switch (header.command_id) {
    case InitializeSockets::id:
        IPC::HandleIPCCommand<InitializeSockets>(HandleInitializeSockets, thread, thread, context);
        break;

    case Socket::id:
        IPC::HandleIPCCommand<Socket>(HandleSocket, thread, thread, context);
        break;

    case Listen::id:
        IPC::HandleIPCCommand<Listen>(HandleListen, thread, thread, context);
        break;

    case Accept::id:
        IPC::HandleIPCCommand<Accept>(HandleAccept, thread, thread, context);
        break;

    case Bind::id:
        IPC::HandleIPCCommand<Bind>(HandleBind, thread, thread, context);
        break;

    case Connect::id:
        IPC::HandleIPCCommand<Connect>(HandleConnect, thread, thread, context);
        break;

    case RecvFromOther::id:
        IPC::HandleIPCCommand<RecvFromOther>(HandleRecvFromOther, thread, thread, context);
        break;

    case RecvFrom::id:
        IPC::HandleIPCCommand<RecvFrom>(HandleRecvFrom, thread, thread, context);
        break;

    case SendToOther::id:
        IPC::HandleIPCCommand<SendToOther>(HandleSendToOther, thread, thread, context);
        break;

    case SendTo::id:
        IPC::HandleIPCCommand<SendTo>(HandleSendTo, thread, thread, context);
        break;

    case Close::id:
        IPC::HandleIPCCommand<Close>(HandleClose, thread, thread, context);
        break;

    case Shutdown::id:
        IPC::HandleIPCCommand<Shutdown>(HandleShutdown, thread, thread, context);
        break;

    case GetHostByName::id:
        IPC::HandleIPCCommand<GetHostByName>(HandleGetHostByName, thread, thread, context);
        break;

    case GetHostByAddr::id:
        IPC::HandleIPCCommand<GetHostByAddr>(HandleGetHostByAddr, thread, thread, context);
        break;

    case GetAddrInfo::id:
        IPC::HandleIPCCommand<GetAddrInfo>(HandleGetAddrInfo, thread, thread, context);
        break;

    case GetNameInfo::id:
        IPC::HandleIPCCommand<GetNameInfo>(HandleGetNameInfo, thread, thread, context);
        break;

    case GetSockOpt::id:
        IPC::HandleIPCCommand<GetSockOpt>(HandleGetSockOpt, thread, thread, context);
        break;

    case SetSockOpt::id:
        IPC::HandleIPCCommand<SetSockOpt>(HandleSetSockOpt, thread, thread, context);
        break;

    case Fcntl::id:
        IPC::HandleIPCCommand<Fcntl>(HandleFcntl, thread, thread, context);
        break;

    case Poll::id:
        IPC::HandleIPCCommand<Poll>(HandlePoll, thread, thread, context);
        break;

    case SockAtMark::id:
        IPC::HandleIPCCommand<SockAtMark>(HandleSockAtMark, thread, thread, context);
        break;

    case GetHostId::id:
        IPC::HandleIPCCommand<GetHostId>(HandleGetHostId, thread, thread, context);
        break;

    case GetSockName::id:
        IPC::HandleIPCCommand<GetSockName>(HandleGetSockName, thread, thread, context);
        break;

    case GetPeerName::id:
        IPC::HandleIPCCommand<GetPeerName>(HandleGetPeerName, thread, thread, context);
        break;

    case ShutdownSockets::id:
        IPC::HandleIPCCommand<ShutdownSockets>(HandleShutdownSockets, thread, thread, context);
        break;

    case GetNetworkOpt::id:
        IPC::HandleIPCCommand<GetNetworkOpt>(HandleGetNetworkOpt, thread, thread, context);
        break;

    case SendToMultiple::id:
        IPC::HandleIPCCommand<SendToMultiple>(HandleSendToMultiple, thread, thread, context);
        break;

    case CloseSockets::id:
        IPC::HandleIPCCommand<CloseSockets>(HandleCloseSockets, thread, thread, context);
        break;

    case AddGlobalSocket::id:
        IPC::HandleIPCCommand<AddGlobalSocket>(HandleAddGlobalSocket, thread, thread, context);
        break;

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown {} service command with header {:#010x}", service_name, header.raw);
    }

    return ServiceHelper::SendReply;
}

OS::ResultAnd<uint32_t, Handle> HandleCommand7(FakeThread& thread, FakeSOC& context) {
    // This event seems to be related with NWM::SOC command 0x00090000. If the event
    // is signaled, AC will then call soc:P command 0x00080000.
    context.socp_event.second->SignalEvent();
    return std::make_tuple(RESULT_OK, CTR_ESUCCESS, context.socp_event.first);
}

OS::ResultAnd<uint32_t> HandleCommand8(FakeThread& thread, FakeSOC& context) {
    return std::make_tuple(RESULT_OK, CTR_ESUCCESS);
}

static decltype(ServiceHelper::SendReply) SOCPCommandHandler(FakeThread& thread, FakeSOC& context, std::string_view service_name, uint32_t, const IPC::CommandHeader& header) {
    using Command7 = IPC::IPCCommand<0x7>::response::add_uint32::add_handle<IPC::HandleType::Event>;
    using Command8 = IPC::IPCCommand<0x8>::response::add_uint32;

    switch (header.command_id) {

    case Command7::id:
        IPC::HandleIPCCommand<Command7>(HandleCommand7, thread, thread, context);
        break;

    case Command8::id:
        IPC::HandleIPCCommand<Command8>(HandleCommand8, thread, thread, context);
        break;

    default:
        throw Mikage::Exceptions::NotImplemented("Unknown {} service command with header {:#010x}", service_name, header.raw);
    }

    return ServiceHelper::SendReply;
}

void FakeSOC::ServiceThread(FakeThread& thread, const char* service_name, const uint32_t max_sessions,
                            decltype(ServiceHelper::SendReply) (*command_handler)(FakeThread&, FakeSOC&, std::string_view, uint32_t, const IPC::CommandHeader&)) {
    ServiceHelper service;
    service.Append(ServiceUtil::SetupService(thread, service_name, max_sessions));

    auto InvokeCommandHandler = [&](FakeThread& thread, uint32_t signalled_handle_index) {
        Platform::IPC::CommandHeader header = { thread.ReadTLS(0x80) };
        return command_handler(thread, *this, service_name, signalled_handle_index, header);
    };

    service.Run(thread, std::move(InvokeCommandHandler));
}

FakeSOC::FakeSOC(FakeThread& thread) {
    thread.name = "SOCThread";

    src_addr_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x1C), 0x1C, 0 };
    thread.WriteTLS(0x180, IPC::TranslationDescriptor::MakeStaticBuffer(0, 0x1C).raw);
    thread.WriteTLS(0x184, src_addr_buffer.addr);

    dst_addr_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x1C), 0x1C, 1 };
    thread.WriteTLS(0x188, IPC::TranslationDescriptor::MakeStaticBuffer(1, 0x1C).raw);
    thread.WriteTLS(0x18C, dst_addr_buffer.addr);

    send_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x2000), 0x2000, 2 };
    thread.WriteTLS(0x190, IPC::TranslationDescriptor::MakeStaticBuffer(2, 0x2000).raw);
    thread.WriteTLS(0x194, send_buffer.addr);

    name_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x100), 0x100, 3 };
    thread.WriteTLS(0x198, IPC::TranslationDescriptor::MakeStaticBuffer(3, 0x100).raw);
    thread.WriteTLS(0x19C, name_buffer.addr);

    hostent_addr_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x1C), 0x1C, 4 };
    thread.WriteTLS(0x1A0, IPC::TranslationDescriptor::MakeStaticBuffer(4, 0x1C).raw);
    thread.WriteTLS(0x1A4, hostent_addr_buffer.addr);

    node_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x100), 0x100, 5 };
    thread.WriteTLS(0x1A8, IPC::TranslationDescriptor::MakeStaticBuffer(5, 0x100).raw);
    thread.WriteTLS(0x1AC, node_buffer.addr);

    service_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x100), 0x100, 6 };
    thread.WriteTLS(0x1B0, IPC::TranslationDescriptor::MakeStaticBuffer(6, 0x100).raw);
    thread.WriteTLS(0x1B4, service_buffer.addr);

    hints_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x130), 0x130, 7 };
    thread.WriteTLS(0x1B8, IPC::TranslationDescriptor::MakeStaticBuffer(7, 0x130).raw);
    thread.WriteTLS(0x1BC, hints_buffer.addr);

    nameinfo_addr_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x1C), 0x1C, 8 };
    thread.WriteTLS(0x1C0, IPC::TranslationDescriptor::MakeStaticBuffer(8, 0x1C).raw);
    thread.WriteTLS(0x1C4, hostent_addr_buffer.addr);

    optval_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x2000), 0x2000, 9 };
    thread.WriteTLS(0x1C8, IPC::TranslationDescriptor::MakeStaticBuffer(9, 0x2000).raw);
    thread.WriteTLS(0x1CC, optval_buffer.addr);

    pollfds_buffer = { thread.GetParentProcess().AllocateStaticBuffer(0x2000), 0x2000, 10 };
    thread.WriteTLS(0x1D0, IPC::TranslationDescriptor::MakeStaticBuffer(10, 0x2000).raw);
    thread.WriteTLS(0x1D4, pollfds_buffer.addr);

    {
        Result result;
        std::tie(result,socp_event) = thread.CallSVC(&OS::SVCCreateEvent, ResetType::Sticky);
        if (result != RESULT_OK) {
            throw std::runtime_error("Failed to create soc:P event");
        }

        auto new_thread = std::make_shared<WrappedFakeThread>(  thread.GetParentProcess(),
                                                                [this](FakeThread& thread) { ServiceThread(thread, "soc:P", 3, SOCPCommandHandler); });
        new_thread->name = "soc:PThread";
        thread.GetParentProcess().AttachThread(new_thread);
    }

    thread.name = "soc:UThread";
    ServiceThread(thread, "soc:U", 18, SOCUCommandHandler);
}

template<> std::shared_ptr<WrappedFakeProcess> CreateFakeProcessViaContext<FakeSOC>(OS& os, Interpreter::Setup& setup, uint32_t pid, const std::string& name) {
    return WrappedFakeProcess::CreateWithContext<FakeSOC>(os, setup, pid, name);
}

} // namespace OS

} // namespace HLE
