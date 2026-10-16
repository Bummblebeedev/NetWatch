#include "connections.h"
#include "process_info.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>

static double GetCurrentTimeSec() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(now.time_since_epoch()).count();
}

static std::string FormatRate(double bps) {
    std::ostringstream ss;
    if (bps < 1024.0) {
        ss << (int)bps << " B/s";
    } else if (bps < 1024.0 * 1024.0) {
        ss << std::fixed << std::setprecision(1) << (bps / 1024.0) << " KB/s";
    } else if (bps < 1024.0 * 1024.0 * 1024.0) {
        ss << std::fixed << std::setprecision(2) << (bps / (1024.0 * 1024.0)) << " MB/s";
    } else {
        ss << std::fixed << std::setprecision(2) << (bps / (1024.0 * 1024.0 * 1024.0)) << " GB/s";
    }
    return ss.str();
}

static std::string FormatBytes(uint64_t bytes) {
    std::ostringstream ss;
    if (bytes < 1024) {
        ss << bytes << " B";
    } else if (bytes < 1024 * 1024) {
        ss << std::fixed << std::setprecision(1) << (bytes / 1024.0) << " KB";
    } else if (bytes < 1024 * 1024 * 1024) {
        ss << std::fixed << std::setprecision(1) << (bytes / (1024.0 * 1024.0)) << " MB";
    } else {
        ss << std::fixed << std::setprecision(2) << (bytes / (1024.0 * 1024.0 * 1024.0)) << " GB";
    }
    return ss.str();
}

static std::string EscapeJson(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if ((unsigned char)c < ' ') {
            o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
        } else {
            o << c;
        }
    }
    return o.str();
}

static std::string TcpStateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTENING";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

ConnectionInspector::ConnectionInspector(Sniffer& sniffer, DNSResolver& dns)
    : sniffer_(sniffer), dns_(dns), last_tick_(GetCurrentTimeSec()) {}

std::string ConnectionInspector::GenerateJsonSnapshot(bool only_active, const std::string& search) {
    double now = GetCurrentTimeSec();
    double dt = std::max(now - last_tick_, 0.001);
    last_tick_ = now;

    // 1. Get Sniffer flows and compute rate deltas
    auto current_flows = sniffer_.GetFlowSnapshot();
    std::map<FlowKey, std::pair<double, double>> rates;
    double total_dl = 0.0;
    double total_ul = 0.0;

    for (const auto& kv : current_flows) {
        const auto& key = kv.first;
        uint64_t cur_dl = kv.second.first;
        uint64_t cur_ul = kv.second.second;

        uint64_t prev_dl = cur_dl;
        uint64_t prev_ul = cur_ul;
        auto pit = prev_flows_.find(key);
        if (pit != prev_flows_.end()) {
            prev_dl = pit->second.first;
            prev_ul = pit->second.second;
        }

        double dl_bps = (cur_dl >= prev_dl) ? (double)(cur_dl - prev_dl) / dt : 0.0;
        double ul_bps = (cur_ul >= prev_ul) ? (double)(cur_ul - prev_ul) / dt : 0.0;
        rates[key] = {dl_bps, ul_bps};
        total_dl += dl_bps;
        total_ul += ul_bps;
    }
    prev_flows_ = current_flows;

    if (total_dl > peak_dl_) peak_dl_ = total_dl;
    if (total_ul > peak_ul_) peak_ul_ = total_ul;

    // 2. Fetch OS TCP Table with Owning PIDs
    std::vector<ConnRecord> os_conns;
    std::map<std::pair<std::string, uint16_t>, std::pair<DWORD, std::string>> port_to_proc;

    ULONG tcpSize = 0;
    GetExtendedTcpTable(NULL, &tcpSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcpSize > 0) {
        std::vector<BYTE> buf(tcpSize);
        PMIB_TCPTABLE_OWNER_PID pTable = (PMIB_TCPTABLE_OWNER_PID)buf.data();
        if (GetExtendedTcpTable(pTable, &tcpSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
                const auto& row = pTable->table[i];
                DWORD pid = row.dwOwningPid;
                std::string app = ProcessManager::Instance().GetProcessName(pid);

                char lBuf[INET_ADDRSTRLEN], rBuf[INET_ADDRSTRLEN];
                struct in_addr lAddr, rAddr;
                lAddr.S_un.S_addr = row.dwLocalAddr;
                rAddr.S_un.S_addr = row.dwRemoteAddr;
                inet_ntop(AF_INET, &lAddr, lBuf, sizeof(lBuf));
                inet_ntop(AF_INET, &rAddr, rBuf, sizeof(rBuf));

                uint16_t lport = ntohs((uint16_t)row.dwLocalPort);
                uint16_t rport = ntohs((uint16_t)row.dwRemotePort);

                port_to_proc[{"TCP", lport}] = {pid, app};

                ConnRecord rec;
                rec.proto = "TCP";
                rec.local_ip = lBuf;
                rec.local_port = lport;
                rec.remote_ip = rBuf;
                rec.remote_port = rport;
                rec.state = TcpStateToString(row.dwState);
                rec.pid = pid;
                rec.app_name = app;
                os_conns.push_back(rec);
            }
        }
    }

    // 3. Fetch OS UDP Table with Owning PIDs
    ULONG udpSize = 0;
    GetExtendedUdpTable(NULL, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (udpSize > 0) {
        std::vector<BYTE> buf(udpSize);
        PMIB_UDPTABLE_OWNER_PID pTable = (PMIB_UDPTABLE_OWNER_PID)buf.data();
        if (GetExtendedUdpTable(pTable, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
                const auto& row = pTable->table[i];
                DWORD pid = row.dwOwningPid;
                std::string app = ProcessManager::Instance().GetProcessName(pid);

                char lBuf[INET_ADDRSTRLEN];
                struct in_addr lAddr;
                lAddr.S_un.S_addr = row.dwLocalAddr;
                inet_ntop(AF_INET, &lAddr, lBuf, sizeof(lBuf));
                uint16_t lport = ntohs((uint16_t)row.dwLocalPort);

                port_to_proc[{"UDP", lport}] = {pid, app};

                ConnRecord rec;
                rec.proto = "UDP";
                rec.local_ip = lBuf;
                rec.local_port = lport;
                rec.remote_ip = "*";
                rec.remote_port = 0;
                rec.state = "LISTENING";
                rec.pid = pid;
                rec.app_name = app;
                os_conns.push_back(rec);
            }
        }
    }

    // 4. Correlate with sniffer flows
    struct AppBucket {
        std::string name;
        double dl = 0.0;
        double ul = 0.0;
        std::map<DWORD, std::vector<ConnRecord>> procs;
    };
    std::map<std::string, AppBucket> apps;
    std::set<std::tuple<DWORD, std::string, std::string, uint16_t>> seen;

    // A. Add active sniffer flows
    for (const auto& kv : rates) {
        const auto& key = kv.first;
        double dl = kv.second.first;
        double ul = kv.second.second;

        auto pit = port_to_proc.find({key.proto, key.local_port});
        if (pit != port_to_proc.end()) {
            DWORD pid = pit->second.first;
            std::string app = pit->second.second;

            ConnRecord rec;
            rec.proto = key.proto;
            rec.local_port = key.local_port;
            rec.local_ip = "";
            rec.remote_ip = key.remote_ip;
            rec.remote_port = key.remote_port;
            rec.state = "Active Stream";
            rec.pid = pid;
            rec.app_name = app;
            rec.dl_rate = dl;
            rec.ul_rate = ul;
            rec.hostname = dns_.GetHostname(key.remote_ip);

            apps[app].name = app;
            apps[app].dl += dl;
            apps[app].ul += ul;
            apps[app].procs[pid].push_back(rec);

            seen.insert({pid, key.proto, key.remote_ip, key.remote_port});
        }
    }

    // B. Add OS Connections
    for (auto& c : os_conns) {
        if (c.remote_ip != "*" && c.remote_ip != "0.0.0.0") {
            if (seen.find({c.pid, c.proto, c.remote_ip, c.remote_port}) == seen.end()) {
                FlowKey k{c.proto, c.local_port, c.remote_ip, c.remote_port};
                auto rit = rates.find(k);
                if (rit != rates.end()) {
                    c.dl_rate = rit->second.first;
                    c.ul_rate = rit->second.second;
                }
                c.hostname = dns_.GetHostname(c.remote_ip);

                apps[c.app_name].name = c.app_name;
                apps[c.app_name].dl += c.dl_rate;
                apps[c.app_name].ul += c.ul_rate;
                apps[c.app_name].procs[c.pid].push_back(c);

                seen.insert({c.pid, c.proto, c.remote_ip, c.remote_port});
            }
        } else {
            if (!only_active) {
                c.hostname = "-";
                apps[c.app_name].name = c.app_name;
                apps[c.app_name].procs[c.pid].push_back(c);
            }
        }
    }

    // 5. Build JSON output
    std::string search_lower = search;
    std::transform(search_lower.begin(), search_lower.end(), search_lower.begin(), ::tolower);

    std::ostringstream json;
    json << "{\n";
    json << "  \"totals\": {\n";
    json << "    \"dlRate\": " << total_dl << ",\n";
    json << "    \"ulRate\": " << total_ul << ",\n";
    json << "    \"dlRateFormatted\": \"" << FormatRate(total_dl) << "\",\n";
    json << "    \"ulRateFormatted\": \"" << FormatRate(total_ul) << "\",\n";
    json << "    \"cumulativeDl\": " << sniffer_.GetCumulativeDl() << ",\n";
    json << "    \"cumulativeUl\": " << sniffer_.GetCumulativeUl() << ",\n";
    json << "    \"cumulativeDlFormatted\": \"" << FormatBytes(sniffer_.GetCumulativeDl()) << "\",\n";
    json << "    \"cumulativeUlFormatted\": \"" << FormatBytes(sniffer_.GetCumulativeUl()) << "\",\n";
    json << "    \"peakDl\": " << peak_dl_ << ",\n";
    json << "    \"peakUl\": " << peak_ul_ << ",\n";
    json << "    \"peakDlFormatted\": \"" << FormatRate(peak_dl_) << "\",\n";
    json << "    \"peakUlFormatted\": \"" << FormatRate(peak_ul_) << "\"\n";
    json << "  },\n";

    // Adapters
    auto adapters = sniffer_.GetActiveAdapters();
    json << "  \"activeAdapters\": [";
    for (size_t i = 0; i < adapters.size(); ++i) {
        json << "\"" << adapters[i] << "\"" << (i + 1 < adapters.size() ? ", " : "");
    }
    json << "],\n";
    json << "  \"paused\": " << (sniffer_.IsPaused() ? "true" : "false") << ",\n";

    // Apps array
    json << "  \"apps\": [\n";
    bool firstApp = true;
    size_t totalConnsCount = 0;
    size_t appCount = 0;

    for (const auto& kv : apps) {
        const auto& app = kv.second;

        // Collect matching processes and conns
        std::vector<std::pair<DWORD, std::vector<ConnRecord>>> matchedProcs;
        size_t appConnCount = 0;

        for (const auto& pkv : app.procs) {
            DWORD pid = pkv.first;
            std::vector<ConnRecord> matchedConns;

            for (const auto& conn : pkv.second) {
                if (!search_lower.empty()) {
                    std::string haystack = app.name + " " + std::to_string(pid) + " " +
                                           conn.remote_ip + ":" + std::to_string(conn.remote_port) + " " +
                                           conn.hostname + " " + conn.proto;
                    std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
                    if (haystack.find(search_lower) == std::string::npos) {
                        continue;
                    }
                }
                if (only_active && conn.dl_rate == 0.0 && conn.ul_rate == 0.0 && conn.state == "LISTENING") {
                    continue;
                }
                matchedConns.push_back(conn);
            }

            if (!matchedConns.empty() || !only_active) {
                appConnCount += matchedConns.size();
                matchedProcs.push_back({pid, matchedConns});
            }
        }

        if (only_active && app.dl == 0.0 && app.ul == 0.0 && appConnCount == 0) {
            continue;
        }
        if (matchedProcs.empty()) continue;

        if (!firstApp) json << ",\n";
        firstApp = false;
        appCount++;
        totalConnsCount += appConnCount;

        json << "    {\n";
        json << "      \"name\": \"" << EscapeJson(app.name) << "\",\n";
        json << "      \"dlRate\": " << app.dl << ",\n";
        json << "      \"ulRate\": " << app.ul << ",\n";
        json << "      \"dlRateFormatted\": \"" << FormatRate(app.dl) << "\",\n";
        json << "      \"ulRateFormatted\": \"" << FormatRate(app.ul) << "\",\n";
        json << "      \"connCount\": " << appConnCount << ",\n";

        // PIDs
        json << "      \"pids\": [";
        for (size_t i = 0; i < matchedProcs.size(); ++i) {
            json << matchedProcs[i].first << (i + 1 < matchedProcs.size() ? ", " : "");
        }
        json << "],\n";

        // Processes
        json << "      \"processes\": [\n";
        for (size_t pi = 0; pi < matchedProcs.size(); ++pi) {
            DWORD pid = matchedProcs[pi].first;
            const auto& conns = matchedProcs[pi].second;

            double p_dl = 0.0;
            double p_ul = 0.0;
            for (const auto& c : conns) {
                p_dl += c.dl_rate;
                p_ul += c.ul_rate;
            }

            json << "        {\n";
            json << "          \"pid\": " << pid << ",\n";
            json << "          \"dlRate\": " << p_dl << ",\n";
            json << "          \"ulRate\": " << p_ul << ",\n";
            json << "          \"dlRateFormatted\": \"" << FormatRate(p_dl) << "\",\n";
            json << "          \"ulRateFormatted\": \"" << FormatRate(p_ul) << "\",\n";
            json << "          \"connections\": [\n";

            for (size_t ci = 0; ci < conns.size(); ++ci) {
                const auto& c = conns[ci];
                std::string label = (c.remote_ip == "*")
                                    ? (c.local_ip.empty() ? "0.0.0.0" : c.local_ip) + ":" + std::to_string(c.local_port)
                                    : c.remote_ip + ":" + std::to_string(c.remote_port);

                json << "            {\n";
                json << "              \"label\": \"" << EscapeJson(label) << "\",\n";
                json << "              \"remoteIp\": \"" << EscapeJson(c.remote_ip) << "\",\n";
                json << "              \"remotePort\": " << c.remote_port << ",\n";
                json << "              \"localPort\": " << c.local_port << ",\n";
                json << "              \"proto\": \"" << c.proto << "\",\n";
                json << "              \"hostname\": \"" << EscapeJson(c.hostname) << "\",\n";
                json << "              \"dlRate\": " << c.dl_rate << ",\n";
                json << "              \"ulRate\": " << c.ul_rate << ",\n";
                json << "              \"dlRateFormatted\": \"" << FormatRate(c.dl_rate) << "\",\n";
                json << "              \"ulRateFormatted\": \"" << FormatRate(c.ul_rate) << "\",\n";
                json << "              \"state\": \"" << EscapeJson(c.state) << "\",\n";
                json << "              \"active\": " << ((c.dl_rate > 0 || c.ul_rate > 0) ? "true" : "false") << "\n";
                json << "            }" << (ci + 1 < conns.size() ? "," : "") << "\n";
            }
            json << "          ]\n";
            json << "        }" << (pi + 1 < matchedProcs.size() ? "," : "") << "\n";
        }
        json << "      ]\n";
        json << "    }";
    }
    json << "\n  ],\n";
    json << "  \"appCount\": " << appCount << ",\n";
    json << "  \"totalConns\": " << totalConnsCount << "\n";
    json << "}\n";

    return json.str();
}

std::string ConnectionInspector::GenerateCsvSnapshot() {
    std::ostringstream csv;
    csv << "Application,PID,Protocol,LocalPort,RemoteIP,RemotePort,Hostname,DownloadRate,UploadRate,State\r\n";

    double now = GetCurrentTimeSec();
    double dt = std::max(now - last_tick_, 0.001);

    auto current_flows = sniffer_.GetFlowSnapshot();
    std::map<FlowKey, std::pair<double, double>> rates;

    for (const auto& kv : current_flows) {
        const auto& key = kv.first;
        uint64_t cur_dl = kv.second.first;
        uint64_t cur_ul = kv.second.second;
        uint64_t prev_dl = cur_dl;
        uint64_t prev_ul = cur_ul;
        auto pit = prev_flows_.find(key);
        if (pit != prev_flows_.end()) {
            prev_dl = pit->second.first;
            prev_ul = pit->second.second;
        }
        double dl_bps = (cur_dl >= prev_dl) ? (double)(cur_dl - prev_dl) / dt : 0.0;
        double ul_bps = (cur_ul >= prev_ul) ? (double)(cur_ul - prev_ul) / dt : 0.0;
        rates[key] = {dl_bps, ul_bps};
    }

    ULONG tcpSize = 0;
    GetExtendedTcpTable(NULL, &tcpSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcpSize > 0) {
        std::vector<BYTE> buf(tcpSize);
        PMIB_TCPTABLE_OWNER_PID pTable = (PMIB_TCPTABLE_OWNER_PID)buf.data();
        if (GetExtendedTcpTable(pTable, &tcpSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
                const auto& row = pTable->table[i];
                DWORD pid = row.dwOwningPid;
                std::string app = ProcessManager::Instance().GetProcessName(pid);

                char lBuf[INET_ADDRSTRLEN], rBuf[INET_ADDRSTRLEN];
                struct in_addr lAddr, rAddr;
                lAddr.S_un.S_addr = row.dwLocalAddr;
                rAddr.S_un.S_addr = row.dwRemoteAddr;
                inet_ntop(AF_INET, &lAddr, lBuf, sizeof(lBuf));
                inet_ntop(AF_INET, &rAddr, rBuf, sizeof(rBuf));

                uint16_t lport = ntohs((uint16_t)row.dwLocalPort);
                uint16_t rport = ntohs((uint16_t)row.dwRemotePort);

                FlowKey k{"TCP", lport, rBuf, rport};
                double dl_bps = 0.0, ul_bps = 0.0;
                auto rit = rates.find(k);
                if (rit != rates.end()) {
                    dl_bps = rit->second.first;
                    ul_bps = rit->second.second;
                }
                std::string host = dns_.GetHostname(rBuf);
                std::string state = TcpStateToString(row.dwState);

                csv << "\"" << app << "\"," << pid << ",TCP," << lport << ",\""
                    << rBuf << "\"," << rport << ",\"" << host << "\",\""
                    << FormatRate(dl_bps) << "\",\"" << FormatRate(ul_bps) << "\",\""
                    << state << "\"\r\n";
            }
        }
    }

    ULONG udpSize = 0;
    GetExtendedUdpTable(NULL, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (udpSize > 0) {
        std::vector<BYTE> buf(udpSize);
        PMIB_UDPTABLE_OWNER_PID pTable = (PMIB_UDPTABLE_OWNER_PID)buf.data();
        if (GetExtendedUdpTable(pTable, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
                const auto& row = pTable->table[i];
                DWORD pid = row.dwOwningPid;
                std::string app = ProcessManager::Instance().GetProcessName(pid);
                uint16_t lport = ntohs((uint16_t)row.dwLocalPort);

                csv << "\"" << app << "\"," << pid << ",UDP," << lport << ",\"*\",0,\"-\",\"0 B/s\",\"0 B/s\",\"LISTENING\"\r\n";
            }
        }
    }

    return csv.str();
}
