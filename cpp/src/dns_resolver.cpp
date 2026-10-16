#include "dns_resolver.h"
#include <winsock2.h>
#include <ws2tcpip.h>

DNSResolver::DNSResolver() {
    worker_ = std::thread(&DNSResolver::WorkerLoop, this);
}

DNSResolver::~DNSResolver() {
    running_ = false;
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

std::string DNSResolver::GetHostname(const std::string& ip) {
    if (ip.empty() || ip == "*" || ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::" || ip == "::1") {
        return "-";
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(ip);
    if (it != cache_.end()) {
        return it->second;
    }

    if (pending_.find(ip) == pending_.end()) {
        pending_.insert(ip);
        cache_[ip] = "Resolving...";
        queue_.push(ip);
        cv_.notify_one();
    }

    return cache_[ip];
}

void DNSResolver::WorkerLoop() {
    while (running_) {
        std::string ip;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this]() { return !running_ || !queue_.empty(); });
            if (!running_) break;

            ip = queue_.front();
            queue_.pop();
        }

        std::string hostname = "-";
        struct sockaddr_in sa;
        ZeroMemory(&sa, sizeof(sa));
        sa.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) == 1) {
            char host[NI_MAXHOST];
            if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host),
                            NULL, 0, NI_NAMEREQD) == 0) {
                hostname = host;
            }
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            cache_[ip] = hostname;
            pending_.erase(ip);
        }
    }
}
