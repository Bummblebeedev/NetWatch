import React, { useState, useEffect, useRef } from 'react';
import Header from './Header';
import Waveform from './Waveform';
import Toolbar from './Toolbar';
import StreamCard from './StreamCard';

const MAX_HISTORY = 60;

export default function App() {
  const [snapshot, setSnapshot] = useState(null);
  const [historyDl, setHistoryDl] = useState(() => new Array(MAX_HISTORY).fill(0));
  const [historyUl, setHistoryUl] = useState(() => new Array(MAX_HISTORY).fill(0));
  const [isAdmin, setIsAdmin] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('ALL'); // ALL, ACTIVE, TCP, UDP
  const [expandedApps, setExpandedApps] = useState(() => new Set());
  const [allExpanded, setAllExpanded] = useState(false);
  const [toast, setToast] = useState('');

  const searchInputRef = useRef(null);

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(''), 2800);
  };

  const copyText = (str) => {
    if (!str || str === '-') return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(str).then(() => showToast(`Copied: ${str}`));
    } else {
      const el = document.createElement('input');
      el.value = str;
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      showToast(`Copied: ${str}`);
    }
  };

  // Keyboard shortcut '/'
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === '/' && document.activeElement !== searchInputRef.current) {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Status check
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const res = await fetch('/api/status');
        if (res.ok) {
          const status = await res.json();
          setIsAdmin(status.isAdmin);
          setIsPaused(status.isPaused);
        }
      } catch (e) {}
    };
    checkStatus();
  }, []);

  // Telemetry loop
  useEffect(() => {
    let active = true;

    const fetchSnapshot = async () => {
      if (isPaused) return;

      const onlyActiveParam = (filterType === 'ACTIVE') ? '1' : '0';
      const url = `/api/snapshot?only_active=${onlyActiveParam}&search=${encodeURIComponent(search)}`;

      try {
        const res = await fetch(url);
        if (res.ok && active) {
          const data = await res.json();
          setSnapshot(data);

          const curDl = data.totals?.dlRate || 0;
          const curUl = data.totals?.ulRate || 0;

          setHistoryDl((prev) => {
            const next = [...prev.slice(1), curDl];
            return next;
          });
          setHistoryUl((prev) => {
            const next = [...prev.slice(1), curUl];
            return next;
          });
        }
      } catch (e) {}
    };

    fetchSnapshot();
    const interval = setInterval(fetchSnapshot, 1000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [isPaused, search, filterType]);

  // Keepalive heartbeat
  useEffect(() => {
    const hb = setInterval(() => {
      fetch('/api/heartbeat', { method: 'POST' }).catch(() => {});
    }, 2500);
    return () => clearInterval(hb);
  }, []);

  // Handlers
  const handleElevate = () => {
    fetch('/api/elevate', { method: 'POST' });
  };

  const handleTogglePause = async () => {
    try {
      const res = await fetch('/api/pause', { method: 'POST' });
      const data = await res.json();
      setIsPaused(data.isPaused);
      showToast(data.isPaused ? 'Sniffing Paused' : 'Sniffing Resumed');
    } catch (e) {
      setIsPaused(!isPaused);
    }
  };

  const handleKillProcess = async (pid) => {
    try {
      const res = await fetch(`/api/kill?pid=${pid}`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        showToast(`Terminated PID ${pid}`);
      } else {
        showToast(`Failed to terminate PID ${pid} (Access Denied)`);
      }
    } catch (e) {
      showToast(`Termination request failed for PID ${pid}`);
    }
  };

  // Fixed Export Handler (Dual Mode: Server Desktop Save + Instant Browser Download)
  const handleExport = async (format) => {
    try {
      // 1. Notify server to save to Desktop
      fetch(`/api/export?format=${format}`, { method: 'POST' })
        .then((r) => r.json())
        .then((data) => {
          if (data.success && data.filepath) {
            const fname = data.filepath.split('\\').pop();
            showToast(`Saved to Desktop: ${fname}`);
          }
        })
        .catch(() => {});

      // 2. Direct client-side browser file download
      if (!snapshot) return;

      const dateStr = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      let content = '';
      let mimeType = 'text/plain';
      let filename = `netwatch_export_${dateStr}.${format}`;

      if (format === 'csv') {
        mimeType = 'text/csv;charset=utf-8;';
        const headers = [
          'Application',
          'PID',
          'Protocol',
          'LocalPort',
          'RemoteIP',
          'RemotePort',
          'Hostname',
          'DownloadRate',
          'UploadRate',
          'State',
        ];
        const rows = [headers.join(',')];

        (snapshot.apps || []).forEach((app) => {
          (app.processes || []).forEach((proc) => {
            (proc.connections || []).forEach((conn) => {
              rows.push(
                [
                  `"${app.name}"`,
                  proc.pid,
                  conn.proto,
                  conn.localPort || '',
                  `"${conn.remoteIp}"`,
                  conn.remotePort || '',
                  `"${conn.hostname || ''}"`,
                  `"${conn.dlRateFormatted || ''}"`,
                  `"${conn.ulRateFormatted || ''}"`,
                  `"${conn.state || ''}"`,
                ].join(',')
              );
            });
          });
        });
        content = rows.join('\r\n');
      } else {
        mimeType = 'application/json;charset=utf-8;';
        content = JSON.stringify(snapshot, null, 2);
      }

      const blob = new Blob([content], { type: mimeType });
      const downloadUrl = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(downloadUrl);

      showToast(`Exported ${format.toUpperCase()} successfully`);
    } catch (err) {
      showToast(`Export failed: ${err.message}`);
    }
  };

  const toggleExpandApp = (appName) => {
    setExpandedApps((prev) => {
      const next = new Set(prev);
      if (next.has(appName)) next.delete(appName);
      else next.add(appName);
      return next;
    });
  };

  const handleToggleExpandAll = () => {
    const nextState = !allExpanded;
    setAllExpanded(nextState);
    if (nextState && snapshot?.apps) {
      setExpandedApps(new Set(snapshot.apps.map((a) => a.name)));
    } else {
      setExpandedApps(new Set());
    }
  };

  // Filter apps by protocol
  const apps = (snapshot?.apps || [])
    .map((app) => {
      if (filterType === 'TCP' || filterType === 'UDP') {
        const filteredProcs = (app.processes || [])
          .map((proc) => ({
            ...proc,
            connections: (proc.connections || []).filter((c) => c.proto === filterType),
          }))
          .filter((p) => p.connections.length > 0);

        const connCount = filteredProcs.reduce((acc, p) => acc + p.connections.length, 0);
        return { ...app, processes: filteredProcs, connCount };
      }
      return app;
    })
    .filter((app) => app.connCount > 0);

  const totals = snapshot?.totals || {};
  const activeSocketsCount = snapshot?.totalConns || 0;
  const adapters = snapshot?.activeAdapters || [];

  return (
    <div className="ai-app">
      <div className="ambient-glow cyan-glow" />
      <div className="ambient-glow purple-glow" />

      <Header
        totals={totals}
        isAdmin={isAdmin}
        isPaused={isPaused}
        onTogglePause={handleTogglePause}
        onElevate={handleElevate}
        onExport={handleExport}
      />

      <main className="ai-stage">
        <Waveform
          historyDl={historyDl}
          historyUl={historyUl}
          totals={totals}
          activeSockets={activeSocketsCount}
        />

        <Toolbar
          search={search}
          onSearchChange={setSearch}
          activeFilter={filterType}
          onFilterChange={setFilterType}
          allExpanded={allExpanded}
          onToggleExpandAll={handleToggleExpandAll}
          searchInputRef={searchInputRef}
        />

        <section className="streams-section">
          <div className="streams-header">
            <div className="col-app">APPLICATION / STREAM</div>
            <div className="col-throughput">THROUGHPUT</div>
            <div className="col-proto">PROTOCOL</div>
            <div className="col-host">HOST / DOMAIN</div>
            <div className="col-state">STATE</div>
            <div className="col-action">ACTION</div>
          </div>

          <div className="streams-list">
            {apps.length === 0 ? (
              <div className="loading-state">
                <div className="neural-pulse" />
                <span>Listening on active network adapters...</span>
              </div>
            ) : (
              apps.map((app) => (
                <StreamCard
                  key={app.name}
                  app={app}
                  isExpanded={allExpanded || expandedApps.has(app.name)}
                  onToggleExpand={() => toggleExpandApp(app.name)}
                  onKillProcess={handleKillProcess}
                  onCopy={copyText}
                />
              ))
            )}
          </div>
        </section>
      </main>

      <footer className="ai-footer">
        <div className="f-left">
          <span className="f-pulse" />
          <span>
            {adapters.length > 0
              ? `Promiscuous Sniffing: ${adapters.join(', ')}`
              : 'Raw Socket Sniffer Active (Loopback / All IPv4 Interfaces)'}
          </span>
        </div>
        <div className="f-right">
          <span className="f-accent">Native C++ Engine • React 18 UI</span>
        </div>
      </footer>

      <div className={`toast ${toast ? 'show' : ''}`}>{toast}</div>
    </div>
  );
}
