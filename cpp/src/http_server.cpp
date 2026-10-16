#include "http_server.h"
#include "embedded_assets.h"
#include "elevation.h"
#include "process_info.h"
#include <sstream>
#include <iostream>
#include <fstream>
#include <chrono>
#include <shlobj.h>

static double GetCurrentTimeSec() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(now.time_since_epoch()).count();
}

static std::string GetDesktopPath() {
    wchar_t path[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, path) == S_OK) {
        std::wstring ws(path);
        return std::string(ws.begin(), ws.end());
    }
    return ".";
}

HttpServer::HttpServer(ConnectionInspector& inspector, Sniffer& sniffer)
    : inspector_(inspector), sniffer_(sniffer) {}

HttpServer::~HttpServer() {
    Stop();
}

bool HttpServer::Start() {
    listen_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket_ == INVALID_SOCKET) return false;

    sockaddr_in sin;
    ZeroMemory(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = htons(0); // Auto-assign free port

    if (bind(listen_socket_, (sockaddr*)&sin, sizeof(sin)) == SOCKET_ERROR) {
        closesocket(listen_socket_);
        return false;
    }

    int sinLen = sizeof(sin);
    if (getsockname(listen_socket_, (sockaddr*)&sin, &sinLen) == SOCKET_ERROR) {
        closesocket(listen_socket_);
        return false;
    }
    port_ = ntohs(sin.sin_port);

    if (listen(listen_socket_, 32) == SOCKET_ERROR) {
        closesocket(listen_socket_);
        return false;
    }

    running_ = true;
    last_heartbeat_ = GetCurrentTimeSec();
    server_thread_ = std::thread(&HttpServer::ServerLoop, this);
    return true;
}

void HttpServer::Stop() {
    if (!running_) return;
    running_ = false;
    if (listen_socket_ != INVALID_SOCKET) {
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
    }
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
}

double HttpServer::GetSecondsSinceLastHeartbeat() const {
    return GetCurrentTimeSec() - last_heartbeat_;
}

void HttpServer::ServerLoop() {
    while (running_) {
        sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);
        SOCKET client = accept(listen_socket_, (sockaddr*)&clientAddr, &clientLen);
        if (client == INVALID_SOCKET) {
            if (!running_) break;
            continue;
        }

        std::thread([this, client]() {
            HandleClient(client);
        }).detach();
    }
}

void HttpServer::HandleClient(SOCKET client) {
    char buf[4096];
    int r = recv(client, buf, sizeof(buf) - 1, 0);
    if (r <= 0) {
        closesocket(client);
        return;
    }
    buf[r] = '\0';

    std::string req(buf);
    std::string method, path;
    std::istringstream reqStream(req);
    reqStream >> method >> path;

    std::string query;
    size_t qpos = path.find('?');
    if (qpos != std::string::npos) {
        query = path.substr(qpos + 1);
        path = path.substr(0, qpos);
    }

    auto getParam = [&query](const std::string& name) -> std::string {
        size_t pos = query.find(name + "=");
        if (pos == std::string::npos) return "";
        pos += name.length() + 1;
        size_t end = query.find('&', pos);
        return (end == std::string::npos) ? query.substr(pos) : query.substr(pos, end - pos);
    };

    std::string contentType = "text/html; charset=utf-8";
    std::string responseBody;
    int statusCode = 200;
    std::string statusText = "OK";

    if (path == "/" || path == "/index.html") {
        has_client_ = true;
        last_heartbeat_ = GetCurrentTimeSec();
        contentType = "text/html; charset=utf-8";
        responseBody = std::string((const char*)INDEX_HTML, INDEX_HTML_LEN);
    } else if (path == "/style.css") {
        contentType = "text/css; charset=utf-8";
        responseBody = std::string((const char*)STYLE_CSS, STYLE_CSS_LEN);
    } else if (path == "/app.js") {
        contentType = "application/javascript; charset=utf-8";
        responseBody = std::string((const char*)APP_JS, APP_JS_LEN);
    } else if (path == "/api/status") {
        has_client_ = true;
        last_heartbeat_ = GetCurrentTimeSec();
        contentType = "application/json";
        std::ostringstream ss;
        ss << "{\n";
        ss << "  \"isAdmin\": " << (IsUserAdmin() ? "true" : "false") << ",\n";
        ss << "  \"isPaused\": " << (sniffer_.IsPaused() ? "true" : "false") << ",\n";
        ss << "  \"activeAdapters\": [";
        auto adapters = sniffer_.GetActiveAdapters();
        for (size_t i = 0; i < adapters.size(); ++i) {
            ss << "\"" << adapters[i] << "\"" << (i + 1 < adapters.size() ? ", " : "");
        }
        ss << "]\n}";
        responseBody = ss.str();
    } else if (path == "/api/snapshot") {
        has_client_ = true;
        last_heartbeat_ = GetCurrentTimeSec();
        contentType = "application/json";
        bool onlyActive = (getParam("only_active") != "0");
        std::string search = getParam("search");
        responseBody = inspector_.GenerateJsonSnapshot(onlyActive, search);
    } else if (path == "/api/icon") {
        std::string appName = getParam("app");
        std::string pidStr = getParam("pid");
        DWORD pid = 0;
        if (!pidStr.empty()) {
            try { pid = (DWORD)std::stoul(pidStr); } catch (...) {}
        }
        std::vector<uint8_t> pngData = ProcessManager::Instance().GetProcessIconPng(pid, appName);
        if (!pngData.empty()) {
            std::ostringstream header;
            header << "HTTP/1.1 200 OK\r\n";
            header << "Content-Type: image/png\r\n";
            header << "Content-Length: " << pngData.size() << "\r\n";
            header << "Cache-Control: public, max-age=86400\r\n";
            header << "Connection: close\r\n";
            header << "Access-Control-Allow-Origin: *\r\n\r\n";

            std::string headerStr = header.str();
            send(client, headerStr.data(), (int)headerStr.size(), 0);
            send(client, (const char*)pngData.data(), (int)pngData.size(), 0);
            closesocket(client);
            return;
        } else {
            statusCode = 404;
            statusText = "Not Found";
            responseBody = "Icon not found";
        }
    } else if (path == "/api/heartbeat") {
        has_client_ = true;
        last_heartbeat_ = GetCurrentTimeSec();
        contentType = "application/json";
        responseBody = "{\"status\":\"alive\"}";
    } else if (path == "/api/elevate") {
        contentType = "application/json";
        responseBody = "{\"success\":true}";
        ElevateProcess();
    } else if (path == "/api/pause") {
        contentType = "application/json";
        bool p = sniffer_.TogglePause();
        responseBody = "{\"isPaused\":" + std::string(p ? "true" : "false") + "}";
    } else if (path == "/api/kill") {
        contentType = "application/json";
        std::string pidStr = getParam("pid");
        DWORD pid = 0;
        if (!pidStr.empty()) {
            pid = (DWORD)std::stoul(pidStr);
        }
        bool success = (pid > 0) && ProcessManager::Instance().KillProcess(pid);
        responseBody = "{\"success\":" + std::string(success ? "true" : "false") + ",\"pid\":" + std::to_string(pid) + "}";
    } else if (path == "/api/export") {
        contentType = "application/json";
        std::string format = getParam("format");
        std::string desktop = GetDesktopPath();
        time_t t = time(NULL);
        char timeBuf[64];
        strftime(timeBuf, sizeof(timeBuf), "%Y%m%d_%H%M%S", localtime(&t));
        std::string fname = (format == "csv") ? ("netwatch_export_" + std::string(timeBuf) + ".csv")
                                              : ("netwatch_export_" + std::string(timeBuf) + ".json");
        std::string fpath = desktop + "\\" + fname;

        std::string payload = (format == "csv") ? inspector_.GenerateCsvSnapshot() : inspector_.GenerateJsonSnapshot(false, "");
        std::ofstream out(fpath, std::ios::out | std::ios::binary);
        if (out.is_open()) {
            out << payload;
            out.close();
            responseBody = "{\"success\":true,\"filepath\":\"" + fpath + "\"}";
        } else {
            responseBody = "{\"success\":false,\"error\":\"Cannot open file for writing\"}";
        }
    } else {
        statusCode = 404;
        statusText = "Not Found";
        responseBody = "Not Found";
    }

    std::ostringstream header;
    header << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    header << "Content-Type: " << contentType << "\r\n";
    header << "Content-Length: " << responseBody.size() << "\r\n";
    header << "Connection: close\r\n";
    header << "Access-Control-Allow-Origin: *\r\n";
    header << "\r\n";

    std::string headerStr = header.str();
    send(client, headerStr.data(), (int)headerStr.size(), 0);
    send(client, responseBody.data(), (int)responseBody.size(), 0);

    closesocket(client);
}
