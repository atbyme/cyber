import { useState, useEffect } from 'react'

export default function ResearchPanel({ onThreatClick }) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [collect, setCollect] = useState(null)
  const [status, setStatus] = useState({})
  const [allThreats, setAllThreats] = useState([])
  const [knowledge, setKnowledge] = useState({})
  const [sources, setSources] = useState({})
  const [insights, setInsights] = useState([])
  const [error, setError] = useState(null)
  const [researchHistory, setResearchHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('sys_research_history') || '[]') } catch { return [] }
  })

  useEffect(() => {
    const load = async () => {
      try {
        const [cR, sR, tR, kR, srcR, iR] = await Promise.all([
          fetch('/api/research/collect').then(r => r.json()),
          fetch('/api/status').then(r => r.json()),
          fetch('/api/threats?limit=300').then(r => r.json()),
          fetch('/api/knowledge').then(r => r.json()),
          fetch('/api/sources').then(r => r.json()),
          fetch('/api/insights').then(r => r.json()),
        ])
        setCollect(cR); setStatus(sR); setAllThreats(Array.isArray(tR) ? tR : [])
        setKnowledge(kR); setSources(srcR); setInsights(Array.isArray(iR) ? iR : [])
        setError(null)
      } catch { setError('Failed to load research data') }
    }
    load()
    const i = setInterval(load, 5000)
    return () => clearInterval(i)
  }, [])

  const doResearch = async () => {
    if (!query.trim()) return
    setLoading(true)
    const q = query.trim()
    try {
      const r = await fetch(`/api/research/deep?query=${encodeURIComponent(q)}`)
      const d = await r.json()
      setResults(d)
      const entry = { q, time: new Date().toISOString(), matches: d.total_matches || 0, sources: d.source_breakdown || {} }
      const updated = [entry, ...researchHistory].slice(0, 200)
      setResearchHistory(updated)
      localStorage.setItem('sys_research_history', JSON.stringify(updated))
    } catch (e) {
      setResults({ query: q, total_matches: 0, error: e.message })
    }
    setLoading(false)
  }

  const forceCollect = async () => {
    try {
      const r = await fetch('/api/research/collect/force', { method: 'POST' })
      const d = await r.json()
      const entry = { q: 'FORCE COLLECT', time: new Date().toISOString(), matches: d.cycle, type: 'collect_force' }
      const updated = [entry, ...researchHistory].slice(0, 200)
      setResearchHistory(updated)
      localStorage.setItem('sys_research_history', JSON.stringify(updated))
    } catch {}
  }

  const totalThreats = status.total_scraped || allThreats.length || 0
  const sourceCount = Object.keys(sources).length
  const k = knowledge
  const totalK = (k.cves || 0) + (k.iocs || 0) + (k.malware || 0) + (k.urls || 0)

  return (
    <div>
      {error && <div className="explain-bar" style={{borderColor:'var(--accent-yellow)'}}><span className="explain-icon">⚠</span><div style={{color:'var(--accent-yellow)'}}>{error}</div></div>}
      <div className="terminal-bar">
        <span className="glitch">CYBER RESEARCH LAB — 24/7 COMPLETE WORLD INTELLIGENCE</span>
        <span className="blink">{totalThreats.toLocaleString()} THREATS · {sourceCount} SOURCES</span>
      </div>

      <div className="explain-bar">
        <span className="explain-icon">🔬</span>
        <div>
          <strong>Complete World Research — 24/7</strong> This panel tracks <strong>everything</strong> scraped from 114+ internet sources.
          Every CVE, IOC, malware sample, phishing URL, dark web leak, and threat report is collected in real-time.
          Search below to research any topic across the full database. <strong>All queries saved to your history.</strong>
        </div>
      </div>

      {/* Complete Stats - Everything Being Tracked */}
      <div className="soc-stats">
        <div className="soc-stat critical">
          <div className="soc-stat-val">{totalThreats.toLocaleString()}</div>
          <div className="soc-stat-lbl">TOTAL THREATS SCRAPED</div>
          <div className="soc-stat-sub">{status.rt_cycle || 0} RT cycles · {status.deep_cycle || 0} deep cycles</div>
        </div>
        <div className="soc-stat high">
          <div className="soc-stat-val">{sourceCount}</div>
          <div className="soc-stat-lbl">ACTIVE SOURCES</div>
          <div className="soc-stat-sub">114+ internet-wide feeds</div>
        </div>
        <div className="soc-stat medium">
          <div className="soc-stat-val">{totalK.toLocaleString()}</div>
          <div className="soc-stat-lbl">AI KNOWLEDGE ITEMS</div>
          <div className="soc-stat-sub">{k.cves||0} CVEs · {k.iocs||0} IOCs · {k.malware||0} malware · {k.urls||0} URLs</div>
        </div>
        <div className="soc-stat low">
          <div className="soc-stat-val">{collect?.history?.length || 0}</div>
          <div className="soc-stat-lbl">RESEARCH CYCLES</div>
          <div className="soc-stat-sub">{status.train_cycle || 0} training cycles</div>
        </div>
      </div>

      {/* Research Collection Status — Complete Scan Info */}
      {collect && (
        <div className="soc-panel" style={{marginBottom:10}}>
          <div className="soc-panel-header">
            COMPLETE RESEARCH COLLECTION — 24/7 INTERNET-WIDE SCANNING
            <span className="soc-badge">Cycle #{collect.cycle || 0}</span>
            <button className="btn btn-primary" style={{fontSize:8,padding:'2px 6px',marginLeft:4}}
              onClick={forceCollect}>⟳ FORCE SCAN NOW</button>
          </div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:6,marginBottom:6}}>
            <div className="malware-detail-grid" style={{gridTemplateColumns:'1fr 1fr'}}>
              <div className="detail-item"><div className="detail-label">Threats in DB</div><div className="detail-value">{collect.threat_map?.reduce((s,c)=>s+c.count,0) || totalThreats}</div></div>
              <div className="detail-item"><div className="detail-label">Countries Mapped</div><div className="detail-value">{collect.threat_map?.length || 0}</div></div>
              <div className="detail-item"><div className="detail-label">Agencies Tracked</div><div className="detail-value">{Object.keys(collect.agency_activity||{}).length}</div></div>
              <div className="detail-item"><div className="detail-label">Research History</div><div className="detail-value">{collect.history?.length || 0}</div></div>
            </div>
            <div>
              <div style={{fontSize:8,color:'var(--text-secondary)',marginBottom:4}}>AGENCY ACTIVITY — LAST CYCLE:</div>
              <div style={{display:'flex',flexDirection:'column',gap:2,maxHeight:100,overflow:'auto'}}>
                {Object.entries(collect.agency_activity || {}).slice(0,8).map(([k,v]) => (
                  <div key={k} className="soc-src-chip" style={{padding:'2px 6px',fontSize:7}}>
                    <span style={{fontWeight:600,textTransform:'uppercase'}}>{k}</span>
                    <span>{v.total_threats} threats</span>
                    <span className="soc-time">{v.timeline_count} timeline pts</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          {collect.history?.length > 0 && (
            <div style={{fontSize:8,color:'var(--text-secondary)',display:'flex',flexDirection:'column',gap:2,maxHeight:100,overflow:'auto'}}>
              <div style={{color:'var(--accent-cyan)',fontWeight:600,marginBottom:2}}>SCAN HISTORY:</div>
              {collect.history.slice().reverse().map((h, i) => (
                <div key={i} className="soc-src-chip" style={{padding:'2px 6px',fontSize:7}}>
                  <span className="soc-src-id">#{h.cycle}</span>
                  <span>{h.count} threats · {h.sources} sources</span>
                  <span className="soc-time">{new Date(h.t).toLocaleString()}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Threat type breakdown from live data */}
      {allThreats.length > 0 && (
        <div className="soc-panel" style={{marginBottom:10}}>
          <div className="soc-panel-header">
            LIVE THREAT DATABASE — COMPLETE VIEW <span className="soc-badge">{allThreats.length} threats shown</span>
          </div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:4,marginBottom:6}}>
            {(() => {
              const types = {}; const sources = {}; const risks = {critical:0,high:0,medium:0,low:0}
              allThreats.forEach(t => {
                types[t.type] = (types[t.type] || 0) + 1
                sources[t.source] = (sources[t.source] || 0) + 1
                const s = t.score || 0; const r = s >= 70 ? 'critical' : s >= 40 ? 'high' : s >= 10 ? 'medium' : 'low'
                risks[r]++
              })
              const topTypes = Object.entries(types).sort((a,b)=>b[1]-a[1]).slice(0,4)
              const topSources = Object.entries(sources).sort((a,b)=>b[1]-a[1]).slice(0,4)
              return <>
                <div>
                  <div style={{fontSize:8,color:'var(--text-secondary)',marginBottom:2}}>TOP THREAT TYPES:</div>
                  {topTypes.map(([k,v]) => <div key={k} className="soc-src-chip" style={{padding:'2px 5px',fontSize:7,marginBottom:1}}><span className={`soc-tag ${k==='cve'?'cve':'url'}`} style={{fontSize:6}}>{k}</span>{v}</div>)}
                </div>
                <div>
                  <div style={{fontSize:8,color:'var(--text-secondary)',marginBottom:2}}>TOP SOURCES:</div>
                  {topSources.map(([k,v]) => <div key={k} className="soc-src-chip" style={{padding:'2px 5px',fontSize:7,marginBottom:1}}><span style={{color:'var(--accent-cyan)'}}>{k}</span> {v}</div>)}
                </div>
                <div>
                  <div style={{fontSize:8,color:'var(--text-secondary)',marginBottom:2}}>RISK DISTRIBUTION:</div>
                  {Object.entries(risks).map(([k,v]) => <div key={k} className="soc-src-chip" style={{padding:'2px 5px',fontSize:7,marginBottom:1,borderColor:k==='critical'?'var(--accent-red)':k==='high'?'var(--accent-yellow)':'var(--border)'}}>
                    <span style={{color:k==='critical'?'var(--accent-red)':k==='high'?'var(--accent-yellow)':k==='medium'?'var(--accent-cyan)':'var(--accent-purple)',fontWeight:600}}>{k.toUpperCase()}</span> {v}
                  </div>)}
                </div>
              </>
            })()}
          </div>
          <div style={{maxHeight:180,overflow:'auto'}}>
            <table className="soc-table">
              <thead><tr><th>TYPE</th><th>SOURCE</th><th>CONTENT</th><th>SCORE</th><th>TIME</th></tr></thead>
              <tbody>
                {allThreats.slice(0,30).map((t,i) => (
                  <tr key={i} className="soc-tr" style={{cursor:'pointer'}} onClick={() => onThreatClick?.(t)}>
                    <td><span className={`soc-tag ${t.type==='cve'?'cve':['ioc','botnet'].includes(t.type)?'ioc':'url'}`} style={{fontSize:7}}>{t.type?.slice(0,8)||'?'}</span></td>
                    <td className="soc-src">{t.source?.slice(0,10)}</td>
                    <td className="soc-desc">{t.instruction?.slice(0,80)||t.url?.slice(0,60)||t.ioc?.slice(0,50)||t.description?.slice(0,60)||'—'}</td>
                    <td style={{fontSize:8,color:t.score>=70?'var(--accent-red)':t.score>=40?'var(--accent-yellow)':'var(--text-secondary)'}}>{t.score||0}</td>
                    <td className="soc-time">{new Date(t.t||Date.now()).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Search */}
      <div className="filters-bar">
        <input className="filter-search" style={{flex:1,fontSize:13,padding:'8px 12px'}}
          placeholder="RESEARCH ANYTHING: company, CVE, IP, malware, country, threat actor, agency..."
          value={query} onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && doResearch()} />
        <button className="btn btn-primary" onClick={doResearch} disabled={loading || !query.trim()}>
          {loading ? '⟳ SEARCHING DATABASE...' : '🔍 DEEP RESEARCH'}
        </button>
        <button className="btn btn-primary" style={{background:'var(--accent-purple)'}} onClick={forceCollect}>
          FORCE RESEARCH COLLECT
        </button>
      </div>

      {/* Deep Research Results */}
      {results && (
        <div className="soc-panel" style={{marginBottom:10}}>
          <div className="soc-panel-header">
            DEEP RESEARCH — "{results.query}" <span className="soc-badge">{results.total_matches} matches in database</span>
          </div>
          {results.source_breakdown && Object.keys(results.source_breakdown).length > 0 && (
            <div style={{marginBottom:4}}>
              <div style={{fontSize:8,color:'var(--text-secondary)',marginBottom:2}}>FOUND ACROSS SOURCES:</div>
              <div className="soc-sources" style={{gap:3}}>
                {Object.entries(results.source_breakdown).slice(0,15).map(([k,v]) => (
                  <span key={k} className="soc-src-chip" style={{padding:'2px 5px',fontSize:7}}>
                    {k}: <strong style={{color:'var(--accent-cyan)'}}>{v}</strong>
                  </span>
                ))}
              </div>
            </div>
          )}
          <div style={{maxHeight:350,overflow:'auto',display:'flex',flexDirection:'column',gap:3}}>
            {results.results?.slice(0,50).map((t, i) => (
              <div key={i} className="soc-src-chip" style={{cursor:'pointer',flexDirection:'column',alignItems:'stretch',padding:'4px 8px'}}
                onClick={() => onThreatClick?.(t)}>
                <div style={{display:'flex',alignItems:'center',gap:6,width:'100%'}}>
                  <span className={`soc-tag ${t.type==='cve'?'cve':['ioc','botnet'].includes(t.type)?'ioc':'url'}`} style={{fontSize:7}}>{t.type||'?'}</span>
                  <span style={{fontSize:8,color:'var(--accent-cyan)'}}>{t.source}</span>
                  <span style={{fontSize:8,flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
                    {t.instruction?.slice(0,120)||t.url?.slice(0,60)||t.ioc?.slice(0,50)||t.description?.slice(0,80)||'—'}
                  </span>
                  <span className="soc-time" style={{fontSize:8}}>{new Date(t.t||Date.now()).toLocaleTimeString()}</span>
                </div>
                {(t.url||t.ioc) && <div style={{fontFamily:'monospace',fontSize:7,color:'var(--accent-yellow)',marginTop:1}}>
                  {t.url?`URL: ${t.url.slice(0,80)}`:''}{t.ioc?`IOC: ${t.ioc.slice(0,60)}`:''}
                </div>}
              </div>
            ))}
            {(!results.results||results.results.length===0) && <div className="soc-empty">No matches in database. Try different terms.</div>}
          </div>
        </div>
      )}

      {/* Research History */}
      {researchHistory.length > 0 && (
        <div className="soc-panel" style={{marginBottom:10}}>
          <div className="soc-panel-header">
            YOUR RESEARCH HISTORY — LOCALSTORAGE <span className="soc-badge">{researchHistory.length} queries</span>
            <button className="btn-icon" onClick={() => { setResearchHistory([]); localStorage.removeItem('sys_research_history') }}
              style={{color:'var(--accent-red)',marginLeft:'auto',fontSize:9}}>CLEAR</button>
          </div>
          <div style={{maxHeight:150,overflow:'auto',display:'flex',flexDirection:'column',gap:2}}>
            {researchHistory.slice(0,50).map((h, i) => (
              <div key={i} className="soc-src-chip" style={{cursor:'pointer',padding:'3px 8px',fontSize:8,opacity:1-i*0.01}}
                onClick={() => { if (h.q && h.q !== 'FORCE COLLECT') { setQuery(h.q); setTimeout(() => doResearch(), 100) } }}>
                <span className={`soc-tag ${h.type==='collect_force'?'ioc':h.matches>0?'cve':'info'}`} style={{fontSize:6}}>
                  {h.type==='collect_force'?'SCAN':h.matches>0?`${h.matches}H`:'QRY'}
                </span>
                <span style={{fontWeight:600}}>{h.q?.slice(0,60)||'Force Collect'}</span>
                {h.matches!==undefined && <span style={{color:'var(--accent-cyan)',fontSize:7}}>{h.matches} found</span>}
                <span className="soc-time">{new Date(h.time).toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {!results && researchHistory.length === 0 && (
        <div className="soc-panel">
          <div className="soc-empty" style={{fontSize:11,lineHeight:2}}>
            🔍 Enter any search term above to research the entire threat database.<br/>
            Search for: company names, CVE-XXXX-XXXX, IP addresses, malware variants, countries, threat actors...
          </div>
        </div>
      )}
    </div>
  )
}
