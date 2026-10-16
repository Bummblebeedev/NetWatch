#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <cstdint>

class ProcessManager {
public:
    static ProcessManager& Instance();

    std::string GetProcessName(DWORD pid);
    bool KillProcess(DWORD pid);
    std::vector<uint8_t> GetProcessIconPng(DWORD pid, const std::string& appName);

private:
    ProcessManager();
    ~ProcessManager();

    std::unordered_map<DWORD, std::string> name_cache_;
    std::unordered_map<DWORD, std::wstring> path_cache_;
    std::unordered_map<std::string, std::vector<uint8_t>> icon_cache_;
    std::mutex mutex_;
    ULONG_PTR gdiplus_token_ = 0;
};
