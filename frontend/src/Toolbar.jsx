import React from 'react';

export default function Toolbar({
  search,
  onSearchChange,
  activeFilter,
  onFilterChange,
  allExpanded,
  onToggleExpandAll,
  searchInputRef,
}) {
  return (
    <section className="filter-strip">
      <div className="search-wrap">
        <svg className="search-ico" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <input
          ref={searchInputRef}
          type="text"
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search applications, PIDs, remote IPs, or hostnames..."
          autoComplete="off"
        />
        <span className="search-hint">/</span>
      </div>

      <div className="filter-chips">
        <button
          className={`chip ${activeFilter === 'ALL' ? 'active' : ''}`}
          onClick={() => onFilterChange('ALL')}
        >
          All
        </button>
        <button
          className={`chip ${activeFilter === 'ACTIVE' ? 'active' : ''}`}
          onClick={() => onFilterChange('ACTIVE')}
        >
          Active Only
        </button>
        <button
          className={`chip ${activeFilter === 'TCP' ? 'active' : ''}`}
          onClick={() => onFilterChange('TCP')}
        >
          TCP
        </button>
        <button
          className={`chip ${activeFilter === 'UDP' ? 'active' : ''}`}
          onClick={() => onFilterChange('UDP')}
        >
          UDP
        </button>
      </div>

      <div className="action-chips">
        <button className="chip ghost-chip" onClick={onToggleExpandAll}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="7 13 12 18 17 13"/>
            <polyline points="7 6 12 11 17 6"/>
          </svg>
          <span>{allExpanded ? 'Collapse All' : 'Expand All'}</span>
        </button>
      </div>
    </section>
  );
}
