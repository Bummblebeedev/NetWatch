#pragma once
#include <string>
#include <unordered_map>
#include <queue>
#include <set>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>

class DNSResolver {
public:
    DNSResolver();
    ~DNSResolver();

    std::string GetHostname(const std::string& ip);

private:
    void WorkerLoop();

    std::unordered_map<std::string, std::string> cache_;
    std::set<std::string> pending_;
    std::queue<std::string> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> running_{true};
    std::thread worker_;
};
