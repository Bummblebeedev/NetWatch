#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <chrono>
#include <thread>

#include "elevation.h"
#include "dns_resolver.h"
#include "sniffer.h"
#include "connections.h"
#include "http_server.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }

    // Initialize subsystems
    DNSResolver dns;
    Sniffer sniffer;
    sniffer.Start();

    ConnectionInspector inspector(sniffer, dns);
    HttpServer server(inspector, sniffer);

    if (!server.Start()) {
        MessageBoxW(NULL, L"Failed to initialize internal HTTP server on loopback interface.",
                    L"NetWatch Pro Error", MB_ICONERROR);
        WSACleanup();
        return 1;
    }

    uint16_t port = server.GetPort();
    std::string url = "http://127.0.0.1:" + std::to_string(port);
    std::wstring wUrl(url.begin(), url.end());

    // Launch Microsoft Edge in dedicated Application Window mode
    std::wstring edgeArgs = L"--app=" + wUrl + L" --window-size=1280,820";
    HINSTANCE hEdge = ShellExecuteW(NULL, L"open", L"msedge.exe", edgeArgs.c_str(), NULL, SW_SHOWNORMAL);

    if ((INT_PTR)hEdge <= 32) {
        // Fallback: open default web browser
        ShellExecuteW(NULL, L"open", wUrl.c_str(), NULL, NULL, SW_SHOWNORMAL);
    }

    // Keep running while client is active
    // Gracefully exit when client closes window (heartbeat timeout)
    bool clientSeen = false;
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        if (server.HasActiveClient()) {
            clientSeen = true;
        }

        // If client was connected and heartbeats ceased for > 6 seconds, exit
        if (clientSeen && server.GetSecondsSinceLastHeartbeat() > 6.0) {
            break;
        }
    }

    server.Stop();
    sniffer.Stop();
    WSACleanup();

    return 0;
}
