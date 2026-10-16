#include "process_info.h"
#include <gdiplus.h>
#include <shellapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>

static int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)malloc(size);
    if (!pImageCodecInfo) return -1;
    Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
    for (UINT j = 0; j < num; ++j) {
        if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[j].Clsid;
            free(pImageCodecInfo);
            return j;
        }
    }
    free(pImageCodecInfo);
    return -1;
}

// Convert HICON to high-quality 32bpp ARGB PNG with intact smooth alpha channel
static std::vector<uint8_t> HIconToProperPng(HICON hIcon) {
    std::vector<uint8_t> result;
    if (!hIcon) return result;

    ICONINFO ii;
    if (!GetIconInfo(hIcon, &ii)) return result;

    BITMAP bm;
    int width = 0;
    int height = 0;
    bool hasColor = (ii.hbmColor != NULL);

    if (hasColor) {
        GetObject(ii.hbmColor, sizeof(bm), &bm);
        width = bm.bmWidth;
        height = bm.bmHeight;
    } else if (ii.hbmMask) {
        GetObject(ii.hbmMask, sizeof(bm), &bm);
        width = bm.bmWidth;
        height = bm.bmHeight / 2; // Monochrome mask contains AND + XOR masks
    }

    if (width <= 0 || height <= 0) {
        if (ii.hbmColor) DeleteObject(ii.hbmColor);
        if (ii.hbmMask) DeleteObject(ii.hbmMask);
        return result;
    }

    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);

    BITMAPINFO bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = width;
    bi.bmiHeader.biHeight = -height; // Top-down DIB
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    std::vector<uint32_t> pixels(width * height, 0);

    if (hasColor) {
        GetDIBits(hdcMem, ii.hbmColor, 0, height, pixels.data(), &bi, DIB_RGB_COLORS);

        // Check if color bitmap contains real anti-aliased alpha values
        bool hasAlpha = false;
        for (int i = 0; i < width * height; ++i) {
            if ((pixels[i] & 0xFF000000) != 0) {
                hasAlpha = true;
                break;
            }
        }

        // If no alpha in hbmColor, derive alpha from hbmMask
        if (!hasAlpha && ii.hbmMask) {
            std::vector<uint32_t> maskPixels(width * height, 0);
            GetDIBits(hdcMem, ii.hbmMask, 0, height, maskPixels.data(), &bi, DIB_RGB_COLORS);
            for (int i = 0; i < width * height; ++i) {
                if ((maskPixels[i] & 0x00FFFFFF) == 0) {
                    pixels[i] |= 0xFF000000;
                } else {
                    pixels[i] &= 0x00FFFFFF;
                }
            }
        }
    } else if (ii.hbmMask) {
        // Handle monochrome icon
        std::vector<uint32_t> maskPixels(width * height * 2, 0);
        bi.bmiHeader.biHeight = -(height * 2);
        GetDIBits(hdcMem, ii.hbmMask, 0, height * 2, maskPixels.data(), &bi, DIB_RGB_COLORS);
        for (int i = 0; i < width * height; ++i) {
            uint32_t andMask = maskPixels[i] & 0x00FFFFFF;
            uint32_t xorMask = maskPixels[i + width * height] & 0x00FFFFFF;
            if (andMask != 0) {
                pixels[i] = 0x00000000;
            } else if (xorMask != 0) {
                pixels[i] = 0xFFFFFFFF;
            } else {
                pixels[i] = 0xFF000000;
            }
        }
    }

    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    if (ii.hbmColor) DeleteObject(ii.hbmColor);
    if (ii.hbmMask) DeleteObject(ii.hbmMask);

    // Create GDI+ 32bpp ARGB Bitmap and copy pixel buffer
    Gdiplus::Bitmap bmp(width, height, PixelFormat32bppARGB);
    Gdiplus::BitmapData bmpData;
    Gdiplus::Rect rect(0, 0, width, height);
    if (bmp.LockBits(&rect, Gdiplus::ImageLockModeWrite, PixelFormat32bppARGB, &bmpData) == Gdiplus::Ok) {
        uint8_t* pDst = (uint8_t*)bmpData.Scan0;
        uint8_t* pSrc = (uint8_t*)pixels.data();
        for (int y = 0; y < height; ++y) {
            memcpy(pDst + y * bmpData.Stride, pSrc + y * width * 4, width * 4);
        }
        bmp.UnlockBits(&bmpData);

        CLSID pngClsid;
        if (GetEncoderClsid(L"image/png", &pngClsid) != -1) {
            IStream* pStream = NULL;
            if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK) {
                if (bmp.Save(pStream, &pngClsid, NULL) == Gdiplus::Ok) {
                    STATSTG stat;
                    if (pStream->Stat(&stat, STATFLAG_NONAME) == S_OK) {
                        result.resize((size_t)stat.cbSize.QuadPart);
                        LARGE_INTEGER liZero;
                        liZero.QuadPart = 0;
                        pStream->Seek(liZero, STREAM_SEEK_SET, NULL);
                        ULONG read = 0;
                        pStream->Read(result.data(), (ULONG)result.size(), &read);
                    }
                }
                pStream->Release();
            }
        }
    }

    return result;
}

// Find application executable path via SearchPath, Registry App Paths, or Windows paths
static std::wstring FindAppExecutablePath(const std::string& appName) {
    if (appName.empty()) return L"";

    std::wstring wApp(appName.begin(), appName.end());

    // 1. SearchPath
    wchar_t found[MAX_PATH];
    if (SearchPathW(NULL, wApp.c_str(), L".exe", MAX_PATH, found, NULL)) {
        return found;
    }

    // 2. Windows Registry App Paths (HKLM and HKCU)
    std::wstring exeName = wApp;
    if (exeName.length() < 4 || exeName.substr(exeName.length() - 4) != L".exe") {
        exeName += L".exe";
    }
    std::wstring subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exeName;
    wchar_t pathBuf[MAX_PATH];
    DWORD bufSize = sizeof(pathBuf);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, subkey.c_str(), NULL, RRF_RT_REG_SZ, NULL, pathBuf, &bufSize) == ERROR_SUCCESS) {
        return pathBuf;
    }
    bufSize = sizeof(pathBuf);
    if (RegGetValueW(HKEY_CURRENT_USER, subkey.c_str(), NULL, RRF_RT_REG_SZ, NULL, pathBuf, &bufSize) == ERROR_SUCCESS) {
        return pathBuf;
    }

    // 3. System32 directory
    wchar_t sysDir[MAX_PATH];
    if (GetSystemDirectoryW(sysDir, MAX_PATH)) {
        std::wstring candidate = std::wstring(sysDir) + L"\\" + exeName;
        if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return candidate;
        }
    }

    // 4. Windows directory
    wchar_t winDir[MAX_PATH];
    if (GetWindowsDirectoryW(winDir, MAX_PATH)) {
        std::wstring candidate = std::wstring(winDir) + L"\\" + exeName;
        if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return candidate;
        }
    }

    return L"";
}

// Extract high-resolution icon (64x64, 48x48, or large 32x32)
static HICON ExtractHighResIcon(const std::wstring& path) {
    if (path.empty()) return NULL;

    HICON hIcon = NULL;

    // 1. Try PrivateExtractIconsW for high-DPI 64x64 or 48x48 icon
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) hUser32 = LoadLibraryA("user32.dll");
    if (hUser32) {
        typedef UINT (WINAPI *PrivateExtractIconsW_t)(LPCWSTR, int, int, int, HICON*, UINT*, UINT, UINT);
        PrivateExtractIconsW_t pPrivateExtract = (PrivateExtractIconsW_t)(void(*)())GetProcAddress(hUser32, "PrivateExtractIconsW");
        if (pPrivateExtract) {
            UINT iconId = 0;
            // 64x64
            if (pPrivateExtract(path.c_str(), 0, 64, 64, &hIcon, &iconId, 1, LR_LOADFROMFILE) > 0 && hIcon) {
                return hIcon;
            }
            // 48x48
            if (pPrivateExtract(path.c_str(), 0, 48, 48, &hIcon, &iconId, 1, LR_LOADFROMFILE) > 0 && hIcon) {
                return hIcon;
            }
            // 32x32
            if (pPrivateExtract(path.c_str(), 0, 32, 32, &hIcon, &iconId, 1, LR_LOADFROMFILE) > 0 && hIcon) {
                return hIcon;
            }
        }
    }

    // 2. Try ExtractIconExW for large icon
    HICON hLarge = NULL, hSmall = NULL;
    if (ExtractIconExW(path.c_str(), 0, &hLarge, &hSmall, 1) > 0 && hLarge) {
        if (hSmall) DestroyIcon(hSmall);
        return hLarge;
    }
    if (hSmall) DestroyIcon(hSmall);

    // 3. Try SHGetFileInfoW with SHGFI_LARGEICON
    SHFILEINFOW sfi;
    ZeroMemory(&sfi, sizeof(sfi));
    if (SHGetFileInfoW(path.c_str(), 0, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_LARGEICON) && sfi.hIcon) {
        return sfi.hIcon;
    }

    return NULL;
}

ProcessManager::ProcessManager() {
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    Gdiplus::GdiplusStartup(&gdiplus_token_, &gdiplusStartupInput, NULL);
}

ProcessManager::~ProcessManager() {
    if (gdiplus_token_) {
        Gdiplus::GdiplusShutdown(gdiplus_token_);
        gdiplus_token_ = 0;
    }
}

ProcessManager& ProcessManager::Instance() {
    static ProcessManager instance;
    return instance;
}

std::string ProcessManager::GetProcessName(DWORD pid) {
    if (pid == 0) return "System Idle Process";
    if (pid == 4) return "System";

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = name_cache_.find(pid);
    if (it != name_cache_.end()) {
        return it->second;
    }

    std::string procName = "Unknown";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
            path_cache_[pid] = std::wstring(path);
            std::wstring ws(path);
            size_t slash = ws.find_last_of(L"\\/");
            if (slash != std::wstring::npos) {
                ws = ws.substr(slash + 1);
            }
            procName = std::string(ws.begin(), ws.end());
        }
        CloseHandle(hProcess);
    }

    if (procName == "Unknown") {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (pe.th32ProcessID == pid) {
                        std::wstring ws(pe.szExeFile);
                        procName = std::string(ws.begin(), ws.end());
                        break;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }

    name_cache_[pid] = procName;
    return procName;
}

bool ProcessManager::KillProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return false;
    BOOL res = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    return res != FALSE;
}

std::vector<uint8_t> ProcessManager::GetProcessIconPng(DWORD pid, const std::string& appName) {
    std::lock_guard<std::mutex> lock(mutex_);

    // 1. Check in-memory cache
    auto cit = icon_cache_.find(appName);
    if (cit != icon_cache_.end() && !cit->second.empty()) {
        return cit->second;
    }

    // 2. Locate executable path
    std::wstring fullPath;
    auto pit = path_cache_.find(pid);
    if (pit != path_cache_.end()) {
        fullPath = pit->second;
    }

    if (fullPath.empty() && pid > 0) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess) {
            wchar_t pathBuf[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, pathBuf, &size)) {
                fullPath = pathBuf;
                path_cache_[pid] = fullPath;
            }
            CloseHandle(hProcess);
        }
    }

    // 3. Extract high-res icon from process path
    HICON hIcon = NULL;
    if (!fullPath.empty()) {
        hIcon = ExtractHighResIcon(fullPath);
    }

    // 4. Fallback: Search for executable by application name
    if (!hIcon && !appName.empty()) {
        std::wstring candidatePath = FindAppExecutablePath(appName);
        if (!candidatePath.empty()) {
            hIcon = ExtractHighResIcon(candidatePath);
        }
    }

    // 5. Fallback: Windows generic application icon (Large icon, not small)
    if (!hIcon) {
        SHFILEINFOW sfi;
        ZeroMemory(&sfi, sizeof(sfi));
        if (SHGetFileInfoW(L".exe", FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi),
                           SHGFI_USEFILEATTRIBUTES | SHGFI_ICON | SHGFI_LARGEICON)) {
            hIcon = sfi.hIcon;
        }
    }

    // 6. Convert HICON to crystal-clear 32bpp PNG
    std::vector<uint8_t> pngBytes;
    if (hIcon) {
        pngBytes = HIconToProperPng(hIcon);
        DestroyIcon(hIcon);
    }

    if (!pngBytes.empty()) {
        icon_cache_[appName] = pngBytes;
    }
    return pngBytes;
}
