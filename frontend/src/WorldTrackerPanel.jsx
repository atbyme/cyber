import { useState, useEffect } from 'react'
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

const CONTINENT_COLORS = { NA:'#06b6d4', SA:'#10b981', EU:'#8b5cf6', AF:'#f59e0b', AS:'#ef4444', OC:'#ec4899', UN:'#64748b' }
const CONT_FULL = { NA:'North America', SA:'South America', EU:'Europe', AF:'Africa', AS:'Asia', OC:'Oceania', UN:'Unknown' }

const SEV_COLORS = { critical:'#ef4444', high:'#f59e0b', medium:'#06b6d4', low:'#10b981' }

export default function WorldTrackerPanel({ onThreatClick }) {
  const [countries, setCountries] = useState([])
  const [continents, setContinents] = useState([])
  const [threatStats, setThreatStats] = useState(null)
  const [scraperStatus, setScraperStatus] = useState(null)
  const [dataQuality, setDataQuality] = useState(null)
  const [selectedCountry, setSelectedCountry] = useState(null)
  const [selectedContinent, setSelectedContinent] = useState(null)
  const [viewMode, setViewMode] = useState('all')
  const [error, setError] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [worldHistory, setWorldHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('sys_world_history') || '[]') } catch { return [] }
  })

  const saveWorldClick = (c) => {
    const entry = { code: c.code, name: c.name, threats: c.count||0, t: new Date().toISOString() }
    const updated = [entry, ...worldHistory].slice(0, 100)
    setWorldHistory(updated)
    localStorage.setItem('sys_world_history', JSON.stringify(updated))
  }

  useEffect(() => {
    const load = async () => {
      try {
        const [cR, coR, sR, scR, dR] = await Promise.all([
          fetch('/api/threats/countries').then(r=>r.json()),
          fetch('/api/threats/continents').then(r=>r.json()),
          fetch('/api/threats/stats').then(r=>r.json()),
          fetch('/api/scrapers/status').then(r=>r.json()),
          fetch('/api/data/quality').then(r=>r.json()),
        ])
        setCountries(cR.countries || [])
        setContinents(coR.continents || [])
        setThreatStats(sR)
        setScraperStatus(scR)
        setDataQuality(dR)
        setError(null)
      } catch { setError('Failed to load global threat data') }
    }
    load()
    const i = setInterval(load, 6000)
    return () => clearInterval(i)
  }, [])

  const total = countries.reduce((s,c)=>s+c.count,0)
  const isLive = scraperStatus?.internet_connected && scraperStatus?.source_live > 0
  const liveSources = scraperStatus?.live_sources || []
  const deadSources = scraperStatus?.dead_sources || []
  const verifiedPct = dataQuality?.verified_pct || 0

  const filtered = countries.filter(c => {
    if (selectedContinent && c.continent_code !== selectedContinent) return false
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      return c.name.toLowerCase().includes(q) || c.code.toLowerCase().includes(q)
    }
    return true
  })

  const continentAgg = {}
  countries.forEach(c => {
    const cc = c.continent_code || 'UN'
    if (!continentAgg[cc]) continentAgg[cc] = { code: cc, name: c.continent_name, threats: 0, countries: [], severity: 'low' }
    continentAgg[cc].threats += c.count
    continentAgg[cc].countries.push(c.code)
    const sev = c.count > 10 ? 'critical' : c.count > 5 ? 'high' : c.count > 2 ? 'medium' : 'low'
    continentAgg[cc].severity = continentAgg[cc].severity === 'critical' || sev === 'critical' ? 'critical' :
      continentAgg[cc].severity === 'high' || sev === 'high' ? 'high' : continentAgg[cc].severity === 'medium' || sev === 'medium' ? 'medium' : 'low'
  })
  const continentList = Object.values(continentAgg).sort((a,b) => b.threats - a.threats)

  const chartData = selectedContinent ? filtered.filter(c => c.continent_code === selectedContinent).sort((a,b) => b.count - a.count).slice(0, 15) :
    continentList.map(c => ({ code: c.code, name: c.name, threats: c.threats }))

  return (
    <div>
      {error && <div className="explain-bar" style={{borderColor:'var(--accent-yellow)'}}><span className="explain-icon">⚠</span><div style={{color:'var(--accent-yellow)'}}>{error}</div></div>}

      {/* Internet connectivity & source verification banner */}
      <div className="explain-bar" style={{borderColor: isLive ? 'var(--accent-green)' : 'var(--accent-yellow)'}}>
        <span className="explain-icon">{isLive ? '✓' : '⚠'}</span>
        <div>
          {isLive ? (
            <>
              <strong style={{color:'var(--accent-green)'}}>INTERNET CONNECTED — LIVE DATA</strong>
              {' · '}{scraperStatus.source_live}/{scraperStatus.total_tracked} sources online
              {' · '}{scraperStatus.threats_collected} threats · {scraperStatus.threats_verified} verified
              {liveSources.length > 0 && <span style={{marginLeft:8,fontSize:9,color:'var(--text-secondary)'}}>Sources: {liveSources.slice(0,5).join(', ')}{liveSources.length>5?` +${liveSources.length-5} more`:''}</span>}
            </>
          ) : (
            <>
              <strong style={{color:'var(--accent-yellow)'}}>OFFLINE MODE — FALLBACK DATA</strong>
              {' · '}No verified internet sources available · Showing reference dataset
              {deadSources.length > 0 && <span style={{marginLeft:8,fontSize:9,color:'var(--text-secondary)'}}>Failed: {deadSources.slice(0,5).join(', ')}{deadSources.length>5?` +${deadSources.length-5} more`:''}</span>}
            </>
          )}
        </div>
      </div>

      <div className="terminal-bar">
        <span className="glitch">GLOBAL CYBER THREAT TRACKER — {countries.length} COUNTRIES</span>
        <span className="blink">{isLive ? 'LIVE' : 'OFFLINE'} · {total.toLocaleString()} THREATS · {continentList.length} CONTINENTS</span>
      </div>

      {/* Data quality badge */}
      {dataQuality && (
        <div className="explain-bar">
          <span className="explain-icon">✓</span>
          <div>
            <strong>Research-Grade Data: </strong>
            <strong style={{color:verifiedPct>=30?'var(--accent-green)':'var(--accent-yellow)'}}>{verifiedPct}% verified</strong>
            {' · '}Avg Confidence: <strong>{(dataQuality.avg_confidence||0)}%</strong>
            {' · '}{dataQuality.high_confidence} high-confidence threats
            {' · '}{dataQuality.verified_cross_source} cross-source verified
            {isLive && <span style={{color:'var(--accent-green)',marginLeft:8}}>✓ CONFIRMED LIVE</span>}
          </div>
        </div>
      )}

      <div className="soc-stats">
        <div className="soc-stat critical"><div className="soc-stat-val">{total.toLocaleString()}</div><div className="soc-stat-lbl">GLOBAL THREATS</div><div className="soc-stat-sub">Across {countries.length} countries</div></div>
        <div className="soc-stat high"><div className="soc-stat-val">{countries.length}</div><div className="soc-stat-lbl">COUNTRIES</div><div className="soc-stat-sub">{continentList.map(c=>c.code).join(' · ')}</div></div>
        <div className="soc-stat medium"><div className="soc-stat-val">{continentList.length}</div><div className="soc-stat-lbl">CONTINENTS</div><div className="soc-stat-sub">{isLive ? 'LIVE Verified' : 'Fallback data'}</div></div>
        <div className="soc-stat low"><div className="soc-stat-val">{dataQuality?.high_confidence || 0}</div><div className="soc-stat-lbl">HIGH CONFIDENCE</div><div className="soc-stat-sub">{dataQuality?.verified_cross_source || 0} cross-source verified</div></div>
      </div>

      {/* View mode selector */}
      <div style={{display:'flex',gap:6,marginBottom:10,flexWrap:'wrap',alignItems:'center'}}>
        <button className={`btn ${viewMode==='all'?'btn-primary':'btn-secondary'}`} style={{fontSize:9,padding:'3px 10px'}} onClick={()=>setViewMode('all')}>ALL COUNTRIES</button>
        <button className={`btn ${viewMode==='continent'?'btn-primary':'btn-secondary'}`} style={{fontSize:9,padding:'3px 10px'}} onClick={()=>setViewMode('continent')}>BY CONTINENT</button>
        <button className={`btn ${viewMode==='severity'?'btn-primary':'btn-secondary'}`} style={{fontSize:9,padding:'3px 10px'}} onClick={()=>setViewMode('severity')}>BY SEVERITY</button>
        <div style={{marginLeft:'auto',display:'flex',gap:4}}>
          <input className="soc-input" placeholder="Search country..." value={searchQuery} onChange={e=>setSearchQuery(e.target.value)}
            style={{padding:'3px 8px',fontSize:10,width:140,background:'var(--bg-tertiary)',border:'1px solid var(--border)',borderRadius:4,color:'var(--text-primary)'}} />
        </div>
      </div>

      {/* Charts */}
      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">{selectedContinent ? `${CONT_FULL[selectedContinent]} — TOP 15 COUNTRIES` : 'CONTINENT DISTRIBUTION'} <span className="chart-badge">{chartData.length}</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData.length>0?chartData:[{code:'...',name:'...',threats:0}]}>
                <XAxis dataKey="code" tick={{fontSize:9,fill:'#94a3b8'}} />
                <YAxis tick={{fontSize:8,fill:'#94a3b8'}} />
                <Tooltip contentStyle={{background:'#1a2332',border:'1px solid #2d3a50',borderRadius:6,fontSize:10}} formatter={(v,n,p)=>[v.toLocaleString(),p.payload.name]} />
                <Bar dataKey="threats" radius={[3,3,0,0]}>
                  {chartData.map(d => <Cell key={d.code} fill={CONTINENT_COLORS[d.code]||SEV_COLORS[selectedContinent?countries.find(c=>c.code===d.code)?.severity:'medium']||'#64748b'} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="chart-container">
          <div className="chart-title">GLOBAL SHARE <span className="chart-badge">{total.toLocaleString()} total</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={continentList.length>0?continentList.map(c=>({name:c.code,value:c.threats})):[{name:'...',value:1}]} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} innerRadius={30}>
                  {continentList.map(c => <Cell key={c.code} fill={CONTINENT_COLORS[c.code]||'#64748b'} />)}
                </Pie>
                <Tooltip contentStyle={{background:'#1a2332',border:'1px solid #2d3a50',borderRadius:6,fontSize:10}} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Continent quick filter chips */}
      <div style={{display:'flex',gap:4,marginBottom:10,flexWrap:'wrap'}}>
        <button className={`btn ${!selectedContinent?'btn-primary':'btn-secondary'}`} style={{fontSize:8,padding:'2px 8px'}} onClick={()=>setSelectedContinent(null)}>ALL</button>
        {continentList.map(c => (
          <button key={c.code} className={`btn ${selectedContinent===c.code?'btn-primary':'btn-secondary'}`}
            style={{fontSize:8,padding:'2px 8px',borderColor:CONTINENT_COLORS[c.code]||'var(--border)'}} onClick={()=>setSelectedContinent(selectedContinent===c.code?null:c.code)}>
            {c.code} ({c.threats.toLocaleString()})
          </button>
        ))}
      </div>

      {/* ALL COUNTRIES LIST with full details */}
      <div className="soc-panel">
        <div className="soc-panel-header">
          {selectedContinent ? `${CONT_FULL[selectedContinent]} — ` : ''}ALL COUNTRIES — FULL INTELLIGENCE <span className="soc-badge">{filtered.length} countries</span>
          {isLive && <span className="soc-badge sec" style={{color:'var(--accent-green)'}}>✓ LIVE VERIFIED</span>}
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:3}}>
          {filtered.length === 0 && <div style={{padding:20,textAlign:'center',fontSize:10,color:'var(--text-secondary)'}}>No countries match your filter</div>}
          {filtered.map(c => {
            const pct = total > 0 ? (c.count/total*100).toFixed(1) : 0
            return (
              <div key={c.code} className="soc-src-chip" style={{cursor:'pointer',flexDirection:'column',alignItems:'stretch',padding:'7px 10px',
                borderColor: CONTINENT_COLORS[c.continent_code]||SEV_COLORS[c.severity]||'#64748b',
                borderLeft: `3px solid ${SEV_COLORS[c.severity]||'#64748b'}`,
                boxShadow: selectedCountry?.code===c.code?`0 0 12px ${SEV_COLORS[c.severity]}40`:'none'}}
                onClick={() => { const was = selectedCountry?.code===c.code; setSelectedCountry(was?null:c); if (!was) saveWorldClick(c) }}>
                <div style={{display:'flex',alignItems:'center',gap:6,width:'100%'}}>
                  <span style={{fontWeight:700,fontSize:11,color:SEV_COLORS[c.severity]||'#64748b',minWidth:30}}>{c.code}</span>
                  <span style={{fontWeight:600,fontSize:10,flex:1}}>{c.name}</span>
                  <span className={`soc-tag ${c.severity==='critical'?'cve':c.severity==='high'?'ioc':'url'}`} style={{fontSize:7}}>{c.severity.toUpperCase()}</span>
                  <span style={{fontSize:11,fontWeight:700,color:'var(--accent-red)'}}>{c.count.toLocaleString()}</span>
                  <span style={{fontSize:8,color:'var(--text-secondary)',minWidth:35}}>{pct}%</span>
                  <span style={{fontSize:8,color:CONTINENT_COLORS[c.continent_code]||'var(--text-secondary)'}}>{c.continent_code}</span>
                  {c.samples && c.samples.length > 0 && <span className="soc-badge sec" style={{fontSize:7}}>{c.samples.length} samples</span>}
                </div>
                <div style={{marginTop:3,height:3,background:'var(--bg-tertiary)',borderRadius:2,overflow:'hidden'}}>
                  <div style={{width:`${pct}%`,background:SEV_COLORS[c.severity]||'#64748b',height:'100%',borderRadius:2}} />
                </div>
                {selectedCountry?.code===c.code && (
                  <div style={{marginTop:6,padding:'7px 9px',background:'var(--bg-tertiary)',borderRadius:5,border:'1px solid var(--border)',fontSize:9,lineHeight:1.5}}>
                    <div style={{marginBottom:4}}><strong style={{color:SEV_COLORS[c.severity]}}>{c.name} ({c.code}) — Full Intelligence</strong></div>
                    <div><strong>Threat Count:</strong> {c.count.toLocaleString()} ({pct}% global)</div>
                    <div><strong>Continent:</strong> {c.continent_name} ({c.continent_code})</div>
                    <div><strong>Severity Level:</strong> <span className={`soc-tag ${c.severity==='critical'?'cve':c.severity==='high'?'ioc':'url'}`}>{c.severity.toUpperCase()}</span></div>
                    <div><strong>Coordinates:</strong> {c.lat?.toFixed(2)}, {c.lng?.toFixed(2)}</div>
                    <div><strong>Data Source:</strong> {isLive ? 'Live internet scrape' : 'Reference fallback'} · {dataQuality?.verified_cross_source > 0 ? `${dataQuality.verified_cross_source} sources` : 'No verification'}</div>
                    {c.samples && c.samples.length > 0 && (
                      <div style={{marginTop:4}}>
                        <strong>Sample Threats:</strong>
                        <div style={{maxHeight:80,overflow:'auto',marginTop:3,display:'flex',flexDirection:'column',gap:2}}>
                          {c.samples.map((s, i) => (
                            <div key={i} style={{padding:'2px 5px',background:'var(--bg-secondary)',borderRadius:3,fontSize:8,display:'flex',gap:4,alignItems:'center',cursor:'pointer'}}
                              onClick={e=>{e.stopPropagation();onThreatClick?.(s)}}>
                              <span className={`soc-tag`} style={{fontSize:6,opacity:0.8}}>{s.type||s.source}</span>
                              <span style={{flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{s.desc||s.url||'No details'}</span>
                              {s.verified && <span style={{color:'var(--accent-green)',fontSize:7}}>✓</span>}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    <div style={{marginTop:5,display:'flex',gap:4}}>
                      <button className="btn btn-primary" style={{fontSize:7,padding:'2px 7px'}} onClick={e=>{e.stopPropagation();onThreatClick?.({type:'country',name:c.name,code:c.code,threats:c.count})}}>VIEW ALL THREATS</button>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Continent summary */}
      <div className="soc-panel" style={{marginTop:10}}>
        <div className="soc-panel-header">
          CONTINENT SUMMARY <span className="soc-badge">{continentList.length}</span>
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:3}}>
          {continentList.map(c => {
            const pct = total > 0 ? (c.threats/total*100).toFixed(1) : 0
            return (
              <div key={c.code} className="soc-src-chip" style={{cursor:'pointer',flexDirection:'column',alignItems:'stretch',padding:'6px 10px',
                borderColor: CONTINENT_COLORS[c.code]||'#64748b',
                borderLeft: `3px solid ${CONTINENT_COLORS[c.code]||'#64748b'}`,
                boxShadow: selectedContinent===c.code?`0 0 12px ${CONTINENT_COLORS[c.code]}40`:'none'}}
                onClick={() => { setSelectedContinent(selectedContinent===c.code?null:c.code); setSelectedCountry(null) }}>
                <div style={{display:'flex',alignItems:'center',gap:6,width:'100%'}}>
                  <span style={{fontWeight:700,fontSize:11,color:CONTINENT_COLORS[c.code]||'#64748b',minWidth:30}}>{c.code}</span>
                  <span style={{fontWeight:600,fontSize:10,flex:1}}>{c.name}</span>
                  <span style={{fontSize:10,fontWeight:700,color:'var(--accent-red)'}}>{c.threats.toLocaleString()}</span>
                  <span style={{fontSize:8,color:'var(--text-secondary)'}}>{pct}%</span>
                  <span style={{fontSize:8,color:'var(--accent-cyan)'}}>{c.countries.length} countries</span>
                  <span className={`soc-tag ${c.severity==='critical'?'cve':c.severity==='high'?'ioc':'url'}`} style={{fontSize:7}}>{c.severity.toUpperCase()}</span>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Source status footer */}
      {scraperStatus && (
        <div className="explain-bar" style={{marginTop:10,borderColor: isLive ? 'var(--accent-green)' : 'var(--accent-yellow)'}}>
          <span className="explain-icon">🔌</span>
          <div style={{fontSize:9,display:'flex',gap:12,flexWrap:'wrap'}}>
            <span><strong>Internet:</strong> {isLive ? '✓ Connected' : '✗ Offline'}</span>
            <span><strong>Sources:</strong> {scraperStatus.source_live} live / {scraperStatus.source_dead} dead</span>
            <span><strong>Threats:</strong> {scraperStatus.threats_collected} total / {scraperStatus.threats_verified} verified</span>
            <span><strong>Last scrape:</strong> {scraperStatus.last_scrape ? new Date(scraperStatus.last_scrape).toLocaleTimeString() : 'N/A'}</span>
            <span><strong>Cycle:</strong> {scraperStatus.rt_cycle || 0}</span>
          </div>
        </div>
      )}
    </div>
  )
}
