# NetWatch AI 🚀 (Native C++17 + React 18 Edition)

A high-performance Windows Network Traffic Monitor and Bandwidth Sniffer built with a **100% Native C++ (C++17)** engine and a **React 18** minimalist AI interface with zero Python dependencies.

![Executable Size](https://img.shields.io/badge/Binary_Size-1.3_MB-cyan)
![Backend](https://img.shields.io/badge/Backend-Native_C++17-blue)
![Frontend](https://img.shields.io/badge/Frontend-React_18_%2B_Vite-61dafb)
![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11-purple)

---

## 🌟 Key Features

- **Real Windows Executable Icons (No SVG Icons)**:
  - Dynamically extracts the **real, authentic `.exe` icons** directly from the local Windows operating system using Win32 Shell APIs (`QueryFullProcessImageNameW`, `SHGetFileInfoW`) and GDI+ (`Bitmap::FromHICON` encoded to PNG).
  - Served via `/api/icon?app=...&pid=...` with in-memory caching for zero CPU overhead.
  - Zero SVG application icon dependencies.
- **Fixed & Enhanced Export**:
  - **Dual-Mode Export**: When clicking `Export JSON` or `Export CSV`, the file is automatically saved to your **Windows Desktop** *and* immediately downloaded through your browser download manager via Blob URL!
  - **Valid CSV formatting**: Correctly formats all columns (`Application`, `PID`, `Protocol`, `LocalPort`, `RemoteIP`, `RemotePort`, `Hostname`, `DownloadRate`, `UploadRate`, `State`).
- **React 18 Frontend Architecture**:
  - Full modular React component tree (`App.jsx`, `Header.jsx`, `Waveform.jsx`, `Toolbar.jsx`, `StreamCard.jsx`).
  - Bundled into a single production asset via Vite SingleFile and compiled straight into the C++ binary.
- **Native C++ Engine (< 1.4 MB)**:
  - Zero Python runtime or external DLL dependencies.
  - Windows raw sockets (`socket(AF_INET, SOCK_RAW, IPPROTO_IP)` + `SIO_RCVALL`) in promiscuous mode across all physical and wireless adapters.
  - Native `GetExtendedTcpTable` & `GetExtendedUdpTable` from `iphlpapi.dll` with exact owning PIDs.
  - Non-blocking threaded reverse DNS resolution engine.
  - Ultra-fast native loopback server serving the embedded React bundle.

---

## 📂 Project Structure

```
netfinder/
├── frontend/                   # React 18 + Vite UI Project
│   ├── src/
│   │   ├── App.jsx             # Main React application & state container
│   │   ├── Header.jsx          # Neural orb, live bandwidth capsule, export menu
│   │   ├── Waveform.jsx        # 60s Canvas oscilloscope telemetry chart
│   │   ├── Toolbar.jsx         # Search bar ('/' shortcut) & filter chips
│   │   ├── StreamCard.jsx      # Flow accordion with real Windows extracted icons
│   │   ├── index.css           # Minimalist AI dark theme styles
│   │   └── main.jsx            # React root mount
│   ├── package.json
│   └── vite.config.js          # Vite singlefile bundler configuration
├── cpp/                        # Native C++ Backend
│   ├── include/
│   │   ├── sniffer.h           # Multi-interface raw socket promiscuous packet sniffer
│   │   ├── connections.h       # Connection inspector & CSV/JSON export engine
│   │   ├── process_info.h      # QueryFullProcessImageNameW & PID termination
│   │   ├── dns_resolver.h      # Threaded asynchronous reverse DNS engine
│   │   ├── http_server.h       # Embedded loopback Winsock HTTP server
│   │   ├── embedded_assets.h   # Inlined React production bundle inside C++
│   │   └── elevation.h         # Windows UAC admin privilege check & restarter
│   ├── src/
│   │   ├── sniffer.cpp
│   │   ├── connections.cpp
│   │   ├── process_info.cpp
│   │   ├── dns_resolver.cpp
│   │   ├── http_server.cpp
│   │   ├── elevation.cpp
│   │   └── main.cpp
│   └── tools/
│       └── embed_assets.cpp    # C++ tool to convert React bundle into C++ header
├── assets/
│   └── icon.ico                # Multi-resolution icon (16x16 to 256x256)
├── netwatch.manifest           # UAC Administrator execution manifest
├── netwatch.rc                 # Windows Resource script (embeds icon & manifest)
├── dist/
│   └── NetWatch_Native.exe     # Standalone Native Executable (1.3 MB)
├── build_cpp.bat               # 1-Click build script (React build + C++ compile)
└── README.md
```

---

## 🚀 Running and Building

### 1. Run the Executable
Double-click:
```
dist\NetWatch_Native.exe
``` 