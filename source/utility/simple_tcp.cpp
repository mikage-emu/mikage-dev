#include "simple_tcp.hpp"

#include <winsock2.h>
#include <mswsock.h> // For AcceptEx and GetAcceptExSockaddrs
#include <boost/asio.hpp>

void SimpleTCPServer::SetupAsyncAccept() {
    acceptor.async_accept([&](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            OnClientConnected(std::move(socket));
        }
        SetupAsyncAccept();
    });
}

SimpleTCPServer::SimpleTCPServer(uint16_t port)
    : acceptor(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)) {
    SetupAsyncAccept();
}

void SimpleTCPServer::RunTCPServer() {
    while (io_context.run()) {}
}

void SimpleTCPServer::StopTCPServer() {
    boost::asio::post(io_context, [this]() { io_context.stop(); });
}
