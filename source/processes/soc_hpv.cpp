#include "soc_hpv.hpp"
#include "ipc.hpp"
#include "os_hypervisor_private.hpp"
#include "os.hpp"

#include <platform/soc.hpp>

#include <framework/exceptions.hpp>

namespace HLE {

namespace OS {

namespace HPV {

namespace {

struct SocService : SessionToPort {
    SocService(RefCounted<Port> port_, SOCContext& context_) : SessionToPort(port_, context_) {
    }

    void OnRequest(Hypervisor& hypervisor, Thread& thread, Handle session) override {
        const uint32_t command_header = thread.ReadTLS(0x80);
        auto dispatcher = RequestDispatcher<> { thread, *this, command_header };

        namespace Cmd = Platform::SOC;

        dispatcher.DecodeRequest<Cmd::InitializeSockets>([&](auto& response, uint32_t size, ProcessId process_id, Handle /*shared_mem*/) {
            auto description = fmt::format( "InitializeSockets, size={:#x}, process_id={:#x}",
                                            size, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::Socket>([&](auto& response, uint32_t domain, uint32_t type, uint32_t protocol, ProcessId process_id) {
            auto description = fmt::format( "Socket, domain={:#x}, type={:#x}, protocol={:#x}, process_id={:#x}",
                                            domain, type, protocol, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::Listen>([&](auto& response, uint32_t sockfd, uint32_t backlog, ProcessId process_id) {
            auto description = fmt::format( "Listen, sockfd={:#x}, backlog={:#x}, process_id={:#x}",
                                            sockfd, backlog, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::Accept>([&](auto& response, uint32_t sockfd, uint32_t addrlen, ProcessId process_id) {
            auto description = fmt::format( "Accept, sockfd={:#x}, addrlen={:#x}, process_id={:#x}",
                                            sockfd, addrlen, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::Bind>([&](auto& response, uint32_t sockfd, uint32_t addrlen, ProcessId process_id, IPC::StaticBuffer /*sock_buffer*/) {
            auto description = fmt::format( "Bind, sockfd={:#x}, addrlen={:#x}, process_id={:#x}",
                                            sockfd, addrlen, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::Connect>([&](auto& response, uint32_t sockfd, uint32_t addrlen, ProcessId process_id, IPC::StaticBuffer /*sock_buffer*/) {
            auto description = fmt::format( "Connect, sockfd={:#x}, addrlen={:#x}, process_id={:#x}",
                                            sockfd, addrlen, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::RecvFromOther>([&](auto& response, uint32_t sockfd, uint32_t len, uint32_t flags, uint32_t addrlen, ProcessId process_id, IPC::MappedBuffer /*data_buffer*/) {
            auto description = fmt::format( "RecvFromOther, sockfd={:#x}, len={:#x}, flags={:#x}, addrlen={:#x}, process_id={:#x}",
                                            sockfd, len, flags, addrlen, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::RecvFrom>([&](auto& response, uint32_t sockfd, uint32_t len, uint32_t flags, uint32_t addrlen, ProcessId process_id) {
            auto description = fmt::format( "RecvFrom, sockfd={:#x}, len={:#x}, flags={:#x}, addrlen={:#x}, process_id={:#x}",
                                            sockfd, len, flags, addrlen, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::SendToOther>([&](auto& response, uint32_t sockfd, uint32_t len, uint32_t flags, uint32_t addrlen, ProcessId process_id, IPC::StaticBuffer /*sock_buffer*/, IPC::MappedBuffer /*data_buffer*/) {
            auto description = fmt::format( "SendToOther, sockfd={:#x}, len={:#x}, flags={:#x}, addrlen={:#x}, process_id={:#x}",
                                            sockfd, len, flags, addrlen, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::SendTo>([&](auto& response, uint32_t sockfd, uint32_t len, uint32_t flags, uint32_t addrlen, ProcessId process_id, IPC::StaticBuffer /*data_buffer*/, IPC::StaticBuffer /*sock_buffer*/) {
            auto description = fmt::format( "SendTo, sockfd={:#x}, len={:#x}, flags={:#x}, addrlen={:#x}, process_id={:#x}",
                                            sockfd, len, flags, addrlen, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::Close>([&](auto& response, uint32_t sockfd, ProcessId process_id) {
            auto description = fmt::format( "Close, sockfd={:#x}, process_id={:#x}",
                                            sockfd, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::Shutdown>([&](auto& response, uint32_t sockfd, uint32_t how, ProcessId process_id) {
            auto description = fmt::format( "Shutdown, sockfd={:#x}, how={:#x}, process_id={:#x}",
                                            sockfd, how, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::GetHostByName>([&](auto& response, uint32_t name_size, uint32_t out_size, IPC::StaticBuffer /*name_buffer*/) {
            auto description = fmt::format( "GetHostByName, name_size={:#x}, out_size={:#x}",
                                            name_size, out_size);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::GetHostByAddr>([&](auto& response, uint32_t addr_size, uint32_t type, uint32_t out_size, IPC::StaticBuffer /*addr_buffer*/) {
            auto description = fmt::format( "GetHostByAddr, addr_size={:#x}, type={:#x}, out_size={:#x}",
                                            addr_size, type, out_size);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::GetAddrInfo>([&](auto& response, uint32_t node_size, uint32_t service_size, uint32_t hints_size, uint32_t out_size, IPC::StaticBuffer /*node_buffer*/, IPC::StaticBuffer /*service_buffer*/, IPC::StaticBuffer /*hints_buffer*/) {
            auto description = fmt::format( "GetAddrInfo, node_size={:#x}, service_size={:#x}, hints_size={:#x}, out_size={:#x}",
                                            node_size, service_size, hints_size, out_size);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::GetNameInfo>([&](auto& response, uint32_t addrlen, uint32_t host_size, uint32_t serv_size, uint32_t flags, IPC::StaticBuffer /*sock_addr_buffer*/) {
            auto description = fmt::format( "GetNameInfo, addrlen={:#x}, host_size={:#x}, serv_size={:#x}, flags={:#x}",
                                            addrlen, host_size, serv_size, flags);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::GetSockOpt>([&](auto& response, uint32_t sockfd, uint32_t level, uint32_t optname, uint32_t optlen, ProcessId process_id) {
            auto description = fmt::format( "GetSockOpt, sockfd={:#x}, level={:#x}, optname={:#x}, optlen={:#x}, process_id={:#x}",
                                            sockfd, level, optname, optlen, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::SetSockOpt>([&](auto& response, uint32_t sockfd, uint32_t level, uint32_t optname, uint32_t optlen, ProcessId process_id, IPC::StaticBuffer /*optval_buffer*/) {
            auto description = fmt::format( "SetSockOpt, sockfd={:#x}, level={:#x}, optname={:#x}, optlen={:#x}, process_id={:#x}",
                                            sockfd, level, optname, optlen, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::Fcntl>([&](auto& response, uint32_t sockfd, uint32_t cmd, uint32_t arg, ProcessId process_id) {
            auto description = fmt::format( "Fcntl, sockfd={:#x}, cmd={:#x}, arg={:#x}, process_id={:#x}",
                                            sockfd, cmd, arg, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::Poll>([&](auto& response, uint32_t nfds, uint32_t timeout, ProcessId process_id, IPC::StaticBuffer /*pollfd_buffer*/) {
            auto description = fmt::format( "Poll, nfds={:#x}, timeout={:#x}, process_id={:#x}",
                                            nfds, timeout, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::SockAtMark>([&](auto& response, uint32_t sockfd, ProcessId process_id) {
            auto description = fmt::format( "SockAtMark, sockfd={:#x}, process_id={:#x}",
                                            sockfd, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::GetHostId>([&](auto& response) {
            Session::OnRequest(hypervisor, thread, session, "GetHostId");
        });

        dispatcher.DecodeRequest<Cmd::GetSockName>([&](auto& response, uint32_t sockfd, uint32_t addrlen, ProcessId process_id) {
            auto description = fmt::format( "GetSockName, sockfd={:#x}, addrlen={:#x}, process_id={:#x}",
                                            sockfd, addrlen, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::GetPeerName>([&](auto& response, uint32_t sockfd, uint32_t addrlen, ProcessId process_id) {
            auto description = fmt::format( "GetPeerName, sockfd={:#x}, addrlen={:#x}, process_id={:#x}",
                                            sockfd, addrlen, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::ShutdownSockets>([&](auto& response) {
            Session::OnRequest(hypervisor, thread, session, "ShutdownSockets");
        });

        dispatcher.DecodeRequest<Cmd::GetNetworkOpt>([&](auto& response, uint32_t level, uint32_t optname, uint32_t optlen) {
            auto description = fmt::format( "GetNetworkOpt, level={:#x}, optname={:#x}, optlen={:#x}",
                                            level, optname, optlen);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::SendToMultiple>([&](auto& response, uint32_t sockfd, uint32_t len, uint32_t flags, uint32_t addrlen, uint32_t socks_size, ProcessId process_id, IPC::StaticBuffer /*data_buffer*/, IPC::StaticBuffer /*socks_buffer*/) {
            auto description = fmt::format( "SendToMultiple, sockfd={:#x}, len={:#x}, flags={:#x}, addrlen={:#x}, socks_size={:#x}, process_id={:#x}",
                                            sockfd, len, flags, addrlen, socks_size, process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::CloseSockets>([&](auto& response, ProcessId process_id) {
            auto description = fmt::format( "CloseSockets, process_id={:#x}",
                                            process_id);
            Session::OnRequest(hypervisor, thread, session, description);
        });

        dispatcher.DecodeRequest<Cmd::AddGlobalSocket>([&](auto& response, uint32_t sockfd) {
            auto description = fmt::format( "AddGlobalSocket, sockfd={:#x}",
                                            sockfd);
            Session::OnRequest(hypervisor, thread, session, description);
        });
    }
};

} // anonymous namespace

HPV::RefCounted<Object> CreateSocService(RefCounted<Port> port, SOCContext& context) {
    return HPV::RefCounted<Object>(new SocService(port, context));
}

} // namespace HPV

} // namespace OS

} // namespace HLE
