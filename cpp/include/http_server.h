#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <atomic>
#include <thread>
#include "connections.h"
#include "sniffer.h"

class HttpServer {
public:
    HttpServer(ConnectionInspector& inspector, Sniffer& sniffer);
    ~HttpServer();

    bool Start();
    void Stop();
    uint16_t GetPort() const { return port_; }

    bool HasActiveClient() const { return has_client_; }
    double GetSecondsSinceLastHeartbeat() const;

private:
    void ServerLoop();
    void HandleClient(SOCKET client);

    ConnectionInspector& inspector_;
    Sniffer& sniffer_;

    uint16_t port_ = 0;
    SOCKET listen_socket_ = INVALID_SOCKET;
    std::atomic<bool> running_{false};
    std::thread server_thread_;

    std::atomic<bool> has_client_{false};
    std::atomic<double> last_heartbeat_{0.0};
};
