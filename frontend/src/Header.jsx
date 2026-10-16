import React, { useState } from 'react';

export default function Header({
  totals,
  isAdmin,
  isPaused,
  onTogglePause,
  onElevate,
  onExport,
}) {
  const [showExport, setShowExport] = useState(false);

  return (
    <header className="ai-header">
      <div className="header-left">
        <div className="neural-orb">
          <div className="orb-core" />
          <div className="orb-pulse" />
        </div>
        <div className="brand">
          <span className="brand-name">NetWatch</span>
          <span className="ai-pill">REACT AI</span>
        </div>
      </div>

      <div className="header-center">
        <div className="capsule">
          <div className="capsule-metric dl">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M12 4v16m0 0l-6-6m6 6l6-6"/>
            </svg>
            <span>{totals.dlRateFormatted || '0 B/s'}</span>
          </div>
          <div className="capsule-sep" />
          <div className="capsule-metric ul">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M12 20V4m0 0l-6 6m6-6l6 6"/>
            </svg>
            <span>{totals.ulRateFormatted || '0 B/s'}</span>
          </div>
        </div>
      </div>

      <div className="header-right">
        {isAdmin ? (
          <div className="status-chip admin">
            <span className="chip-dot" />
            <span>Admin Active</span>
          </div>
        ) : (
          <>
            <div className="status-chip user">
              <span className="chip-dot" />
              <span>Standard Mode</span>
            </div>
            <button
              className="action-btn elevate-btn"
              onClick={onElevate}
              title="Restart with Administrator privileges for raw socket promiscuous capture"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              <span>Elevate</span>
            </button>
          </>
        )}

        <button
          className="action-btn icon-only"
          onClick={onTogglePause}
          title={isPaused ? 'Resume live sniffing' : 'Pause live sniffing'}
          style={{ color: isPaused ? 'var(--ai-amber)' : 'inherit' }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            {isPaused ? (
              <polygon points="5 3 19 12 5 21 5 3" fill="currentColor"/>
            ) : (
              <>
                <rect x="6" y="4" width="4" height="16" rx="1" fill="currentColor"/>
                <rect x="14" y="4" width="4" height="16" rx="1" fill="currentColor"/>
              </>
            )}
          </svg>
        </button>

        <div className="export-wrap" onMouseLeave={() => setShowExport(false)}>
          <button
            className="action-btn icon-only"
            onClick={() => setShowExport(!showExport)}
            title="Export Telemetry Snapshot"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
          </button>
          {showExport && (
            <div className="export-dropdown" style={{ display: 'block' }}>
              <button onClick={() => { setShowExport(false); onExport('json'); }}>
                Export as JSON
              </button>
              <button onClick={() => { setShowExport(false); onExport('csv'); }}>
                Export as CSV
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
