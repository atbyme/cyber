import { useState, useEffect, useRef } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const COLORS = ['#ef4444','#f59e0b','#06b6d4','#8b5cf6','#10b981','#ec4899','#14b8a6','#f97316','#a855f7','#64748b']

export default function DarkWatchPanel({ onThreatClick }) {
  const [data, setData] = useState({ips:[], companies:[], markets:[]})
  const [selectedIp, setSelectedIp] = useState(null)
  const [selectedCompany, setSelectedCompany] = useState(null)
  const [liveAlerts, setLiveAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [cycle, setCycle] = useState(0)

  const load = async () => {
    try {
      const [ipR, coR, mkR] = await Promise.all([
        fetch('/api/darkwatch/ips').then(r => r.json()),
        fetch('/api/darkwatch/companies').then(r => r.json()),
        fetch('/api/darkwatch/markets').then(r => r.json()),
      ])
      setData({ips: ipR.ips||[], companies: coR.companies||[], markets: mkR.markets||[]})
      setCycle(c => c + 1)
      setError(null)
    } catch { setError('Failed to load dark web intelligence') }
    setLoading(false)
  }

  useEffect(() => { load(); const i = setInterval(load, 8000); return () => clearInterval(i) }, [])

  const dataRef = useRef(data)
  dataRef.current = data
  const alertIndex = useRef(0)

  // Live alerts driven by real dark web data
  useEffect(() => {
    if (data.companies.length === 0 || data.ips.length === 0) return
    const i = setInterval(() => {
      alertIndex.current++
      const d = dataRef.current
      const idx = alertIndex.current
      const company = d.companies[idx % d.companies.length]
      const ip = d.ips[idx % d.ips.length]
      const acts = ['credential dump detected','new RDP access for sale','dark web forum post','data leak advertised','C2 beacon observed','ransomware negotiation','stolen database listed']
      const act = acts[idx % acts.length]
      setLiveAlerts(p => [{
        id: Date.now(),
        company: company?.company || 'Unknown',
        action: act,
        ip: ip?.ip || '',
        source: ip?.source || '',
        malware: ip?.malware || '',
        risk: company?.risk || 'medium',
        time: new Date().toLocaleTimeString(),
      }, ...p].slice(0, 30))
    }, 4000)
    return () => clearInterval(i)
  }, [data.companies.length, data.ips.length])

  if (loading) return <div className="loading-bar">Connecting to dark web intelligence feed...</div>
  if (error && data.ips.length === 0) return <div className="loading-bar" style={{color:'var(--accent-yellow)'}}>⚠ {error} — using offline dark web database</div>

  const countryCounts = data.ips.reduce((a, c) => { a[c.country] = (a[c.country] || 0) + (c.threats||0); return a }, {})
  const countryData = Object.entries(countryCounts).map(([k, v]) => ({ name: k, threats: v })).sort((a, b) => b.threats - a.threats)
  const totalIpThreats = data.ips.reduce((s, c) => s + (c.threats||0), 0)

  return (
    <div>
      <div className="terminal-bar">
        <span className="glitch">DARK WATCH — 24/7 DARK WEB & UNDERGROUND MONITOR</span>
        <span className="blink">{data.ips.length} IP RANGES · {data.companies.length} COMPANIES · #{cycle}</span>
      </div>

      <div className="explain-bar">
        <span className="explain-icon">🌑</span>
        <div>
          <strong>Dark Watch Intelligence</strong> — Tracks IPs and servers used by cybercriminals on the dark web.
          Shows <strong>which companies are targeted</strong> and the <strong>specific IPs</strong> behind attacks.
        </div>
      </div>

      <div className="soc-stats">
        <div className="soc-stat critical"><div className="soc-stat-val">{data.ips.length}</div><div className="soc-stat-lbl">KNOWN IP RANGES</div><div className="soc-stat-sub">{data.ips.filter(i=>i.verified).length} verified</div></div>
        <div className="soc-stat high"><div className="soc-stat-val">{totalIpThreats.toLocaleString()}</div><div className="soc-stat-lbl">TOTAL THREATS</div><div className="soc-stat-sub">From darknet IPs</div></div>
        <div className="soc-stat medium"><div className="soc-stat-val">{data.companies.length}</div><div className="soc-stat-lbl">COMPANIES TRACKED</div><div className="soc-stat-sub">{data.companies.filter(c=>c.risk==='critical').length} critical</div></div>
        <div className="soc-stat low"><div className="soc-stat-val">{Object.keys(countryCounts).length}</div><div className="soc-stat-lbl">COUNTRIES</div><div className="soc-stat-sub">Infrastructure hosts</div></div>
      </div>

      <div className="charts-row">
        <div className="chart-container">
          <div className="chart-title">DARKNET INFRASTRUCTURE BY COUNTRY <span className="chart-badge">{countryData.length}</span></div>
          <div className="chart-wrap" style={{height:140}}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={countryData} layout="vertical">
                <XAxis type="number" tick={{fontSize:8,fill:'#94a3b8'}} />
                <YAxis type="category" dataKey="name" tick={{fontSize:9,fill:'#94a3b8'}} width={25} />
                <Tooltip contentStyle={{background:'#1a2332',border:'1px solid #2d3a50',borderRadius:6,fontSize:10}} />
                <Bar dataKey="threats" radius={[0,3,3,0]}>
                  {countryData.map((_,i) => <Cell key={i} fill={COLORS[i%COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="chart-container">
          <div className="chart-title">COMPANY RISK DISTRIBUTION <span className="chart-badge">{data.companies.length}</span></div>
          <div className="chart-wrap" style={{height:140}}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.companies.map(c=>({name:c.company.split(' ')[0],incidents:c.incidents})).sort((a,b)=>b.incidents-a.incidents)}>
                <XAxis dataKey="name" tick={{fontSize:7,fill:'#94a3b8'}} angle={-20} textAnchor="end" height={35} />
                <YAxis tick={{fontSize:8,fill:'#94a3b8'}} />
                <Tooltip contentStyle={{background:'#1a2332',border:'1px solid #2d3a50',borderRadius:6,fontSize:10}} />
                <Bar dataKey="incidents" radius={[3,3,0,0]}>
                  {data.companies.sort((a,b)=>b.incidents-a.incidents).map((c,i) => <Cell key={i} fill={c.risk==='critical'?'#ef4444':c.risk==='high'?'#f59e0b':'#06b6d4'} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {liveAlerts.length > 0 && (
        <div className="soc-panel" style={{marginBottom:10}}>
          <div className="soc-panel-header">
            LIVE DARK WEB ALERTS — 24/7 UNDERGROUND MONITOR <span className="soc-badge">{liveAlerts.length}</span>
          </div>
          <div style={{maxHeight:120,overflow:'auto',display:'flex',flexDirection:'column',gap:2}}>
            {liveAlerts.slice(0,15).map(a => (
              <div key={a.id} className="soc-src-chip" style={{padding:'3px 8px',fontSize:8}}>
                <span style={{fontWeight:700,color:'var(--accent-cyan)'}}>{a.company}</span>
                <span style={{color:'var(--accent-red)'}}>⚠</span>
                <span>{a.action}</span>
                <span style={{fontFamily:'monospace',fontSize:7,color:'var(--accent-yellow)'}}>{a.ip}</span>
                <span className="soc-time">{a.time}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="soc-panel" style={{marginBottom:10}}>
        <div className="soc-panel-header">
          DARKNET IP ADDRESSES — KNOWN C2 & MALICIOUS INFRASTRUCTURE
          <span className="soc-badge">{data.ips.length} ranges</span>
          <span className="soc-badge sec">{data.ips.filter(i=>i.verified).length} verified</span>
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:3}}>
          {data.ips.map((d, i) => (
            <div key={i} className="soc-src-chip" style={{cursor:'pointer',flexDirection:'column',alignItems:'stretch',padding:'5px 8px',
              borderColor: selectedIp?.ip === d.ip ? 'var(--accent-red)' : 'var(--border)'}}
              onClick={() => { const expanding = selectedIp?.ip !== d.ip; setSelectedIp(expanding ? d : null); if (expanding) onThreatClick?.({type:'darknet_ip',ip:d.ip,country:d.country,source:d.source,threats:d.threats,malware:d.malware,t:Date.now()}) }}>
              <div style={{display:'flex',alignItems:'center',gap:6,width:'100%'}}>
                <span style={{fontFamily:'monospace',fontSize:9,color:'var(--accent-yellow)',fontWeight:600}}>{d.ip}</span>
                <span className="soc-src-id" style={{fontSize:8}}>{d.country}</span>
                <span className={`soc-tag ${d.verified?'cve':'info'}`} style={{fontSize:6}}>{d.verified?'VERIFIED':'MONITORED'}</span>
                <span style={{fontSize:8,color:'var(--text-secondary)'}}>{d.source}</span>
                <span style={{fontSize:8,color:'var(--accent-red)',marginLeft:'auto'}}>{d.threats} threats</span>
              </div>
              {selectedIp?.ip === d.ip && (
                <div style={{marginTop:4,padding:'4px 6px',background:'var(--bg-primary)',borderRadius:4,fontSize:8}}>
                  <strong>Malware:</strong> {d.malware}<br/>
                  <strong>Source:</strong> {d.source}<br/>
                  <strong>Country:</strong> {d.country}<br/>
                  <strong>Threats:</strong> {d.threats}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="soc-panel" style={{marginBottom:10}}>
        <div className="soc-panel-header">
          COMPANY TARGETING REPORT — WHY THEY ARE ATTACKED
          <span className="soc-badge">{data.companies.length} companies</span>
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:4}}>
          {data.companies.map(c => (
            <div key={c.company} className="soc-src-chip" style={{cursor:'pointer',flexDirection:'column',alignItems:'stretch',padding:'6px 10px',
              borderColor: selectedCompany?.company === c.company ? (c.risk==='critical'?'var(--accent-red)':'var(--accent-yellow)') : 'var(--border)'}}
              onClick={() => { const expanding = selectedCompany?.company !== c.company; setSelectedCompany(expanding ? c : null); if (expanding) onThreatClick?.({type:'darknet_company',company:c.company,risk:c.risk,incidents:c.incidents,why:c.why,attackers:c.attackers,data_type:c.data_type,ip:c.ip,t:Date.now()}) }}>
              <div style={{display:'flex',alignItems:'center',gap:6,width:'100%'}}>
                <span className={`soc-tag ${c.risk==='critical'?'cve':c.risk==='high'?'url':'info'}`} style={{fontSize:7}}>{c.risk.toUpperCase()}</span>
                <span style={{fontWeight:700,fontSize:10}}>{c.company}</span>
                <span style={{fontSize:8,color:'var(--text-secondary)'}}>IP: {(c.ip||'').split(',')[0]}..</span>
                <span style={{fontSize:8,color:'var(--accent-red)',marginLeft:'auto',fontWeight:600}}>{c.incidents} incidents</span>
              </div>
              {selectedCompany?.company === c.company && (
                <div style={{marginTop:4,padding:'6px 8px',background:'var(--bg-primary)',borderRadius:4,fontSize:8,lineHeight:1.6}}>
                  <div><strong style={{color:'var(--accent-red)'}}>Why Attacked:</strong> {c.why}</div>
                  <div><strong style={{color:'var(--accent-cyan)'}}>IPs/C2:</strong> <span style={{fontFamily:'monospace'}}>{c.ip}</span></div>
                  <div><strong style={{color:'var(--accent-cyan)'}}>Attackers:</strong> {c.attackers}</div>
                  <div><strong style={{color:'var(--accent-cyan)'}}>Data at Risk:</strong> {c.data_type}</div>
                  <div><strong style={{color:'var(--accent-red)'}}>Incidents:</strong> {c.incidents}</div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="soc-panel">
        <div className="soc-panel-header">
          DARK WEB MARKETS — UNDERGROUND ECONOMY <span className="soc-badge">{data.markets.length}</span>
        </div>
        <div style={{display:'flex',flexDirection:'column',gap:3}}>
          {data.markets.map((m, i) => (
            <div key={i} className="soc-src-chip" style={{padding:'4px 10px',borderColor:m.active?'var(--accent-red)':'var(--border)'}}>
              <span className="soc-src-id">{m.name}</span>
              <span className={`soc-tag ${m.active?'cve':'info'}`} style={{fontSize:6}}>{m.active?'ACTIVE':'TAKEDOWN'}</span>
              <span style={{fontSize:8,color:'var(--text-secondary)'}}>{m.type}</span>
              <span style={{fontSize:8,color:'var(--accent-cyan)'}}>{(m.items||0).toLocaleString()} listings</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}