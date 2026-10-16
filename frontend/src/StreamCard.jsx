import React, { useState } from 'react';

export default function StreamCard({
  app,
  isExpanded,
  onToggleExpand,
  onKillProcess,
  onCopy,
}) {
  const [localExpanded, setLocalExpanded] = useState(false);
  const open = isExpanded !== undefined ? isExpanded : localExpanded;

  const toggle = () => {
    if (onToggleExpand) onToggleExpand();
    else setLocalExpanded(!localExpanded);
  };

  const dlClass = app.dlRate > 0 ? 'gauge-dl' : 'gauge-zero';
  const ulClass = app.ulRate > 0 ? 'gauge-ul' : 'gauge-zero';
  const firstPid = app.pids && app.pids.length > 0 ? app.pids[0] : 0;

  return (
    <div className={`app-card ${open ? 'open' : ''}`}>
      <div className="app-row-bar" onClick={toggle}>
        <div className="app-meta">
          <svg className="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
          <div className="app-avatar-wrapper">
            <img
              src={`/api/icon?app=${encodeURIComponent(app.name)}&pid=${firstPid}`}
              alt=""
              className="app-icon-img"
              width="20"
              height="20"
              draggable="false"
              onError={(e) => {
                e.target.style.display = 'none';
                if (e.target.nextSibling) {
                  e.target.nextSibling.style.display = 'flex';
                }
              }}
            />
            <div className="app-icon-fallback" style={{ display: 'none' }}>
              {app.name.charAt(0).toUpperCase()}
            </div>
          </div>
          <span className="app-title-text" title={app.name}>{app.name}</span>
          <span className="stream-count-pill">{app.connCount} flow{app.connCount !== 1 ? 's' : ''}</span>
        </div>

        <div className="speed-gauge-wrap">
          <span className={dlClass}>↓ {app.dlRateFormatted}</span>
          <span className={ulClass}>↑ {app.ulRateFormatted}</span>
        </div>

        <div className="col-proto">-</div>
        <div className="col-host" style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
          PID {app.pids ? app.pids.join(', ') : ''}
        </div>
        <div className="col-state">
          <span className={`state-tag ${app.dlRate > 0 || app.ulRate > 0 ? 'state-active' : 'state-idle'}`}>
            {app.dlRate > 0 || app.ulRate > 0 ? 'Active' : 'Idle'}
          </span>
        </div>
        <div className="col-action"></div>
      </div>

      {open && (
        <div className="sub-streams">
          {app.processes && app.processes.map((proc) => (
            <div key={proc.pid} className="proc-group">
              <div className="proc-bar">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span className="proc-tag">PID {proc.pid}</span>
                  <span style={{ color: 'var(--text-muted)', fontSize: '10.5px' }}>
                    {proc.connections ? proc.connections.length : 0} socket{proc.connections && proc.connections.length !== 1 ? 's' : ''}
                  </span>
                </div>
                <button
                  className="proc-kill-btn"
                  onClick={(e) => {
                    e.stopPropagation();
                    if (confirm(`Terminate process ${app.name} (PID ${proc.pid})?`)) {
                      onKillProcess(proc.pid);
                    }
                  }}
                >
                  Terminate PID
                </button>
              </div>

              {proc.connections && proc.connections.map((conn, idx) => {
                const protoClass = conn.proto === 'TCP' ? 'proto-tcp' : 'proto-udp';
                const cDlClass = conn.dlRate > 0 ? 'gauge-dl' : 'gauge-zero';
                const cUlClass = conn.ulRate > 0 ? 'gauge-ul' : 'gauge-zero';

                return (
                  <div key={idx} className="leaf-row">
                    <div
                      className="leaf-endpoint"
                      title="Click to copy endpoint"
                      onClick={() => onCopy(conn.remoteIp !== '*' ? conn.remoteIp : conn.label)}
                    >
                      <span className={`leaf-dot ${conn.active ? 'active' : ''}`} />
                      <span>{conn.label}</span>
                    </div>

                    <div className="speed-gauge-wrap">
                      <span className={cDlClass}>↓ {conn.dlRateFormatted}</span>
                      <span className={cUlClass}>↑ {conn.ulRateFormatted}</span>
                    </div>

                    <div className="col-proto">
                      <span className={`proto-tag ${protoClass}`}>{conn.proto}</span>
                    </div>

                    <div
                      className="col-host leaf-host"
                      title="Click to copy domain"
                      onClick={() => onCopy(conn.hostname)}
                    >
                      {conn.hostname || '-'}
                    </div>

                    <div className="col-state">
                      <span className={`state-tag ${conn.active ? 'state-active' : 'state-idle'}`}>
                        {conn.state}
                      </span>
                    </div>
                    <div className="col-action"></div>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
