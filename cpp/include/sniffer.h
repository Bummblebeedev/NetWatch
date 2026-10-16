#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <tuple>
#include <mutex>
#include <thread>
#include <atomic>

struct FlowKey {
    std::string proto;
    uint16_t local_port;
    std::string remote_ip;
    uint16_t remote_port;

    bool operator<(const FlowKey& o) const {
        return std::tie(proto, local_port, remote_ip, remote_port) <
               std::tie(o.proto, o.local_port, o.remote_ip, o.remote_port);
    }
};

struct FlowData {
    uint64_t dl_bytes = 0;
    uint64_t ul_bytes = 0;
    double last_seen = 0.0;
};

class Sniffer {
public:
    Sniffer();
    ~Sniffer();

    bool Start();
    void Stop();
    bool TogglePause();
    bool IsPaused() const { return paused_; }

    std::vector<std::string> GetActiveAdapters();
    std::map<FlowKey, std::pair<uint64_t, uint64_t>> GetFlowSnapshot();

    uint64_t GetCumulativeDl() const { return cumulative_dl_; }
    uint64_t GetCumulativeUl() const { return cumulative_ul_; }

private:
    std::vector<std::string> DetectAdapterIPs();
    void SniffAdapter(const std::string& adapter_ip);

    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::atomic<uint64_t> cumulative_dl_{0};
    std::atomic<uint64_t> cumulative_ul_{0};

    std::vector<std::string> active_adapters_;
    std::map<FlowKey, FlowData> flows_;
    std::mutex mutex_;
    std::vector<std::thread> threads_;
};
