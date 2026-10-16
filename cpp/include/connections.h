#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include "sniffer.h"
#include "dns_resolver.h"

struct ConnRecord {
    std::string proto;
    uint16_t local_port;
    std::string local_ip;
    std::string remote_ip;
    uint16_t remote_port;
    std::string state;
    DWORD pid;
    std::string app_name;
    double dl_rate = 0.0;
    double ul_rate = 0.0;
    std::string hostname;
};

class ConnectionInspector {
public:
    ConnectionInspector(Sniffer& sniffer, DNSResolver& dns);

    std::string GenerateJsonSnapshot(bool only_active, const std::string& search);
    std::string GenerateCsvSnapshot();

private:
    Sniffer& sniffer_;
    DNSResolver& dns_;

    double last_tick_ = 0.0;
    std::map<FlowKey, std::pair<uint64_t, uint64_t>> prev_flows_;

    double peak_dl_ = 0.0;
    double peak_ul_ = 0.0;
};
