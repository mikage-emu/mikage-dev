#pragma once
#include <winsock2.h>
#include <mswsock.h> // For AcceptEx and GetAcceptExSockaddrs

#include <boost/asio/ip/tcp.hpp>

class SimpleTCPServer {
protected:
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor;

    void SetupAsyncAccept();

public:
    SimpleTCPServer(uint16_t port);

    virtual void OnClientConnected(boost::asio::ip::tcp::socket) = 0;

    void RunTCPServer();
    void StopTCPServer();
};
