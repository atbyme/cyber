export default function ThreatDetailModal({ threat, onClose }) {
  if (!threat) return null
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <span className="glitch">THREAT INTELLIGENCE DETAIL</span>
          <button className="btn-icon" onClick={onClose} style={{ color: 'var(--accent-red)' }}>✕</button>
        </div>
        <div className="modal-body">
          <div className="soc-stats" style={{ marginBottom: 10 }}>
            <div className="soc-stat critical" style={{ flex: 1 }}>
              <div className="soc-stat-val" style={{ fontSize: 11 }}>{threat.type || 'Unknown'}</div>
              <div className="soc-stat-lbl">TYPE</div>
            </div>
            <div className="soc-stat high" style={{ flex: 1 }}>
              <div className="soc-stat-val" style={{ fontSize: 11 }}>{threat.source || 'Unknown'}</div>
              <div className="soc-stat-lbl">SOURCE</div>
            </div>
            <div className="soc-stat medium" style={{ flex: 1 }}>
              <div className="soc-stat-val" style={{ fontSize: 11 }}>{new Date(threat.t || Date.now()).toLocaleTimeString()}</div>
              <div className="soc-stat-lbl">TIME</div>
            </div>
          </div>

          <div className="soc-panel" style={{ marginBottom: 8 }}>
            <div className="soc-panel-header">CONTENT</div>
            <div style={{ fontSize: 11, color: 'var(--text-primary)', lineHeight: 1.6, padding: 8, maxHeight: 150, overflow: 'auto' }}>
              {threat.instruction || threat.response || threat.url || threat.ioc || threat.description || 'No details available'}
            </div>
          </div>

          <div className="split-row" style={{ gap: 8 }}>
            <div className="soc-panel half">
              <div className="soc-panel-header">RAW DATA</div>
              <pre style={{ fontSize: 8, maxHeight: 120, overflow: 'auto', color: 'var(--text-secondary)', background: 'var(--bg-primary)', padding: 6, borderRadius: 4 }}>
                {JSON.stringify(threat, null, 2).slice(0, 1500)}
              </pre>
            </div>
            <div className="soc-panel half">
              <div className="soc-panel-header">ACTIONS</div>
              <div style={{ padding: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
                <button className="btn btn-primary" style={{ fontSize: 10, padding: '4px 10px' }}
                  onClick={() => {
                    const text = threat.url || threat.ioc || threat.description || JSON.stringify(threat)
                    navigator.clipboard.writeText(text).then(() => alert('Copied to clipboard'))
                  }}>
                  COPY IOC
                </button>
                <button className="btn btn-primary" style={{ fontSize: 10, padding: '4px 10px' }}
                  onClick={() => window.open(`/api/threats/export`, '_blank')}>
                  EXPORT REPORT
                </button>
                <button className="btn btn-primary" style={{ fontSize: 10, padding: '4px 10px' }}
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(threat, null, 2)], { type: 'application/json' })
                    const a = document.createElement('a')
                    a.href = URL.createObjectURL(blob)
                    a.download = `threat_${Date.now()}.json`
                    a.click()
                  }}>
                  DOWNLOAD JSON
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
