#include "sniffer.h"
#include <mstcpip.h>
#include <iphlpapi.h>
#include <chrono>
#include <iostream>

#ifndef SIO_RCVALL
#define SIO_RCVALL _WSAIOW(IOC_VENDOR, 1)
#endif
#ifndef RCVALL_ON
#define RCVALL_ON 1
#endif
#ifndef RCVALL_OFF
#define RCVALL_OFF 0
#endif

static double GetCurrentTimeSec() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(now.time_since_epoch()).count();
}

Sniffer::Sniffer() {}

Sniffer::~Sniffer() {
    Stop();
}

std::vector<std::string> Sniffer::DetectAdapterIPs() {
    std::vector<std::string> ips;
    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufLen);

    if (pAddresses) {
        DWORD flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        if (GetAdaptersAddresses(AF_INET, flags, NULL, pAddresses, &bufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufLen);
        }

        if (pAddresses && GetAdaptersAddresses(AF_INET, flags, NULL, pAddresses, &bufLen) == NO_ERROR) {
            PIP_ADAPTER_ADDRESSES curr = pAddresses;
            while (curr) {
                if (curr->OperStatus == IfOperStatusUp) {
                    PIP_ADAPTER_UNICAST_ADDRESS u = curr->FirstUnicastAddress;
                    while (u) {
                        if (u->Address.lpSockaddr->sa_family == AF_INET) {
                            sockaddr_in* sin = (sockaddr_in*)u->Address.lpSockaddr;
                            char ipBuf[INET_ADDRSTRLEN];
                            if (inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf))) {
                                std::string ip(ipBuf);
                                if (ip.rfind("127.", 0) != 0) {
                                    ips.push_back(ip);
                                }
                            }
                        }
                        u = u->Next;
                    }
                }
                curr = curr->Next;
            }
        }
        free(pAddresses);
    }

    if (ips.empty()) {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) == 0) {
            struct hostent* he = gethostbyname(hostname);
            if (he) {
                for (int i = 0; he->h_addr_list[i] != NULL; ++i) {
                    char* ip = inet_ntoa(*(struct in_addr*)he->h_addr_list[i]);
                    if (ip && strncmp(ip, "127.", 4) != 0) {
                        ips.push_back(ip);
                    }
                }
            }
        }
    }

    return ips;
}

bool Sniffer::Start() {
    if (running_) return true;
    running_ = true;
    paused_ = false;

    std::vector<std::string> ips = DetectAdapterIPs();
    for (const auto& ip : ips) {
        threads_.emplace_back(&Sniffer::SniffAdapter, this, ip);
    }
    return true;
}

void Sniffer::Stop() {
    running_ = false;
    for (auto& t : threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    threads_.clear();
}

bool Sniffer::TogglePause() {
    paused_ = !paused_;
    return paused_;
}

std::vector<std::string> Sniffer::GetActiveAdapters() {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_adapters_;
}

void Sniffer::SniffAdapter(const std::string& adapter_ip) {
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (s == INVALID_SOCKET) return;

    sockaddr_in sin;
    ZeroMemory(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(adapter_ip.c_str());
    sin.sin_port = htons(0);

    if (bind(s, (sockaddr*)&sin, sizeof(sin)) == SOCKET_ERROR) {
        closesocket(s);
        return;
    }

    DWORD inOpt = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char*)&inOpt, sizeof(inOpt)) == SOCKET_ERROR) {
        closesocket(s);
        return;
    }

    DWORD rcvAll = RCVALL_ON;
    DWORD bytesRet = 0;
    if (WSAIoctl(s, SIO_RCVALL, &rcvAll, sizeof(rcvAll), NULL, 0, &bytesRet, NULL, NULL) == SOCKET_ERROR) {
        closesocket(s);
        return;
    }

    // Set 1-second timeout
    DWORD timeout = 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    {
        std::lock_guard<std::mutex> lock(mutex_);
        active_adapters_.push_back(adapter_ip);
    }

    std::vector<char> buffer(65536);

    while (running_) {
        if (paused_) {
            Sleep(200);
            continue;
        }

        int bytesRead = recv(s, buffer.data(), (int)buffer.size(), 0);
        if (bytesRead < 28) continue; // Min IPv4 + TCP/UDP header size

        unsigned char* pkt = (unsigned char*)buffer.data();
        int ihl = (pkt[0] & 0x0F) * 4;
        if (bytesRead < ihl + 4) continue;

        unsigned char proto_num = pkt[9];
        std::string proto;
        if (proto_num == 6) {
            proto = "TCP";
        } else if (proto_num == 17) {
            proto = "UDP";
        } else {
            continue;
        }

        char srcBuf[INET_ADDRSTRLEN];
        char dstBuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, pkt + 12, srcBuf, sizeof(srcBuf));
        inet_ntop(AF_INET, pkt + 16, dstBuf, sizeof(dstBuf));

        std::string src_ip(srcBuf);
        std::string dst_ip(dstBuf);

        uint16_t src_port = ntohs(*(uint16_t*)(pkt + ihl));
        uint16_t dst_port = ntohs(*(uint16_t*)(pkt + ihl + 2));
        double now = GetCurrentTimeSec();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (src_ip == adapter_ip) {
                // Outgoing (Upload)
                FlowKey key{proto, src_port, dst_ip, dst_port};
                auto& flow = flows_[key];
                flow.ul_bytes += bytesRead;
                flow.last_seen = now;
                cumulative_ul_ += bytesRead;
            } else if (dst_ip == adapter_ip) {
                // Incoming (Download)
                FlowKey key{proto, dst_port, src_ip, src_port};
                auto& flow = flows_[key];
                flow.dl_bytes += bytesRead;
                flow.last_seen = now;
                cumulative_dl_ += bytesRead;
            }
        }
    }

    rcvAll = RCVALL_OFF;
    WSAIoctl(s, SIO_RCVALL, &rcvAll, sizeof(rcvAll), NULL, 0, &bytesRet, NULL, NULL);
    closesocket(s);
}

std::map<FlowKey, std::pair<uint64_t, uint64_t>> Sniffer::GetFlowSnapshot() {
    double now = GetCurrentTimeSec();
    std::lock_guard<std::mutex> lock(mutex_);

    // Prune stale flows > 45s
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (now - it->second.last_seen > 45.0) {
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }

    std::map<FlowKey, std::pair<uint64_t, uint64_t>> result;
    for (const auto& kv : flows_) {
        result[kv.first] = {kv.second.dl_bytes, kv.second.ul_bytes};
    }
    return result;
}
