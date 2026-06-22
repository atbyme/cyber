export default function ThreatDetailModal({ threat, onClose }) {
  if (!threat) return null

  const rawJson = JSON.stringify(threat, null, 2)
  const isCompany = threat.type === 'company' || threat.type === 'company_recon'
  const isAgency = threat.type === 'agency'
  const isContinent = threat.type === 'continent_threats' || threat.type === 'continent'

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()} style={{maxWidth:650}}>
        <div className="modal-header">
          <span className="glitch">
            {isCompany ? 'COMPANY THREAT INTELLIGENCE' :
             isAgency ? 'AGENCY INTELLIGENCE REPORT' :
             isContinent ? 'CONTINENT THREAT REPORT' :
             'THREAT INTELLIGENCE DETAIL'}
          </span>
          <button className="btn-icon" onClick={onClose} style={{color:'var(--accent-red)'}}>✕</button>
        </div>
        <div className="modal-body" style={{maxHeight:'75vh',overflow:'auto'}}>
          <div className="soc-stats" style={{marginBottom:10}}>
            <div className="soc-stat critical" style={{flex:1,padding:6}}>
              <div className="soc-stat-val" style={{fontSize:11}}>{threat.type || threat.name || 'Unknown'}</div>
              <div className="soc-stat-lbl">TYPE</div>
            </div>
            <div className="soc-stat high" style={{flex:1,padding:6}}>
              <div className="soc-stat-val" style={{fontSize:11}}>{threat.source || threat.country || threat.ticker || '—'}</div>
              <div className="soc-stat-lbl">SOURCE / ORIGIN</div>
            </div>
            <div className="soc-stat medium" style={{flex:1,padding:6}}>
              <div className="soc-stat-val" style={{fontSize:11}}>{new Date(threat.t || Date.now()).toLocaleTimeString()}</div>
              <div className="soc-stat-lbl">TIME</div>
            </div>
          </div>

          {/* Threat Intelligence Content */}
          <div className="soc-panel" style={{marginBottom:8}}>
            <div className="soc-panel-header">INTELLIGENCE CONTENT</div>
            <div style={{fontSize:11,color:'var(--text-primary)',lineHeight:1.6,padding:8,maxHeight:150,overflow:'auto'}}>
              {threat.instruction || threat.response || threat.url || threat.ioc || threat.description || threat.name || 'No details available'}
            </div>
          </div>

          {/* Full Detective Details - All raw data */}
          <div className="soc-panel" style={{marginBottom:8}}>
            <div className="soc-panel-header">RAW INTELLIGENCE DATA — FULL ANALYSIS</div>
            <div style={{fontSize:9,color:'var(--text-secondary)',lineHeight:1.8}}>
              {Object.entries(threat).filter(([k]) => !['instruction','response','description','url','ioc','t','type','source','name','country','ticker'].includes(k)).map(([k,v]) => (
                <div key={k} style={{padding:'2px 0',borderBottom:'1px solid rgba(45,58,80,0.3)'}}>
                  <strong style={{color:'var(--accent-cyan)',textTransform:'uppercase',fontSize:8}}>{k.replace(/_/g,' ')}:</strong>{' '}
                  <span>{typeof v === 'object' && v !== null ? JSON.stringify(v).slice(0,300) : String(v).slice(0,300)}</span>
                </div>
              )).concat(
                // Always show all fields including standard ones
                Object.entries(threat).filter(([k]) => ['instruction','response','description','url','ioc','type','source','name','country','ticker'].includes(k)).map(([k,v]) => (
                  <div key={k} style={{padding:'2px 0',borderBottom:'1px solid rgba(45,58,80,0.3)'}}>
                    <strong style={{color:'var(--accent-yellow)',textTransform:'uppercase',fontSize:8}}>{k.replace(/_/g,' ')}:</strong>{' '}
                    <span>{typeof v === 'object' && v !== null ? JSON.stringify(v).slice(0,300) : String(v).slice(0,300)}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Raw JSON */}
          <div className="soc-panel">
            <div className="soc-panel-header">RAW JSON</div>
            <pre style={{fontSize:7,maxHeight:200,overflow:'auto',color:'var(--text-secondary)',background:'var(--bg-primary)',padding:8,borderRadius:4,whiteSpace:'pre-wrap',wordBreak:'break-all'}}>
              {rawJson.slice(0, 3000)}
            </pre>
          </div>

          <div className="split-row" style={{gap:8,marginTop:8}}>
            <div className="soc-panel half">
              <div className="soc-panel-header">ACTIONS</div>
              <div style={{padding:8,display:'flex',flexDirection:'column',gap:6}}>
                <button className="btn btn-primary" style={{fontSize:10,padding:'4px 10px'}} onClick={() => { const text = threat.url||threat.ioc||threat.description||threat.name||JSON.stringify(threat); navigator.clipboard.writeText(text).then(() => alert('Copied to clipboard')) }}>
                  COPY IOC
                </button>
                <button className="btn btn-primary" style={{fontSize:10,padding:'4px 10px'}} onClick={() => window.open('/api/threats/export','_blank')}>
                  EXPORT REPORT
                </button>
                <button className="btn btn-primary" style={{fontSize:10,padding:'4px 10px'}} onClick={() => { const blob = new Blob([rawJson],{type:'application/json'}); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `threat_${Date.now()}.json`; a.click() }}>
                  DOWNLOAD JSON
                </button>
              </div>
            </div>
            <div className="soc-panel half">
              <div className="soc-panel-header">DETECTIVE NOTES</div>
              <div style={{padding:8,fontSize:9,color:'var(--text-secondary)',lineHeight:1.6}}>
                {isCompany && <div>Company threat intel report. Track all related IPs, domains, breaches, and open ports for this organization.</div>}
                {isAgency && <div>Agency intelligence profile. Contains known operations, tactics, targets, tools, and detected activity in the wild.</div>}
                {isContinent && <div>Continent-wide threat analysis. Shows attack distribution, top targeted countries, and risk assessment per region.</div>}
                {!isCompany && !isAgency && !isContinent && <div>Individual threat indicator. Cross-reference with other sources, check for related malware families, and monitor for evolution.</div>}
                <div style={{marginTop:6,padding:4,background:'rgba(239,68,68,0.08)',borderRadius:4}}>
                  <strong style={{color:'var(--accent-red)'}}>⚠ VERIFY BEFORE ACTION:</strong> This intelligence is gathered from passive OSINT sources. Always verify before taking action.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
