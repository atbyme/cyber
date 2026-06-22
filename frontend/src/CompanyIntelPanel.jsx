import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const RISK_COLORS = { critical: '#ef4444', high: '#f59e0b', medium: '#06b6d4', low: '#10b981' }

const SUSPECTED_THREATS = {
  apple: { likely: ['Supply chain malware', 'iCloud credential phishing', 'Zero-day iOS exploits'], target: 'Consumer data, iOS ecosystem' },
  microsoft: { likely: ['Exchange server attacks', 'Azure credential theft', 'Office 365 phishing'], target: 'Enterprise email, cloud infra' },
  nvidia: { likely: ['CUDA toolkit exploits', 'GPU driver vulnerabilities', 'AI model IP theft'], target: 'AI/ML infrastructure, driver stack' },
  amazon: { likely: ['AWS credential harvesting', 'S3 data leak scanning', 'E-commerce fraud bots'], target: 'Cloud services, retail data' },
  alphabet: { likely: ['Chrome zero-day exploits', 'Android malware packaging', 'Cloud platform scanning'], target: 'Browser/OS users, cloud tenants' },
  meta: { likely: ['Account takeover bots', 'WhatsApp phishing', 'Ad platform abuse'], target: 'Social media users, messaging' },
  tesla: { likely: ['Infotainment system hacks', 'Autopilot sensor spoofing', 'Factory network breaches'], target: 'Vehicle systems, factory ops' },
  berkshire: { likely: ['Insurance data mining', 'Financial fraud detection', 'Energy grid probing'], target: 'Financial data, energy infra' },
  tsMC: { likely: ['Chip design IP theft', 'Fab tool vulnerabilities', 'Mask data interception'], target: 'Semiconductor IP, fabrication' },
  eli_lilly: { likely: ['Drug formula theft', 'Clinical trial data breach', 'Ransomware on pharma R&D'], target: 'Medical IP, patient data' },
}

const COLORS_PALETTE = ['#ef4444','#f59e0b','#06b6d4','#10b981','#8b5cf6','#ec4899','#14b8a6','#f97316','#64748b','#a855f7']

export default function CompanyIntelPanel({ onThreatClick }) {
  const [top, setTop] = useState([])
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState(null)
  const [companyHistory, setCompanyHistory] = useState(() => {
    try { return JSON.parse(localStorage.getItem('sys_company_history') || '[]') } catch { return [] }
  })

  useEffect(() => {
    const f = async () => { try { const r = await fetch('/api/companies/top'); setTop((await r.json()).companies || []); setError(null) } catch { setError('Failed to load company data') } }
    f(); const i = setInterval(f, 4000); return () => clearInterval(i)
  }, [])

  const saveCompanyClick = (c) => {
    const entry = { name: c.name, ticker: c.ticker, risk: c.risk, t: new Date().toISOString() }
    const updated = [entry, ...companyHistory].slice(0, 100)
    setCompanyHistory(updated)
    localStorage.setItem('sys_company_history', JSON.stringify(updated))
  }

  const barData = top.map(c => ({ name: (c.name||'').split(' ')[0], threats: c.threats||0, attacks: c.attacks||0, breaches: c.breaches||0 }))

  return (
    <div>
      {error && <div className="explain-bar" style={{borderColor:'var(--accent-yellow)'}}><span className="explain-icon">⚠</span><div style={{color:'var(--accent-yellow)'}}>{error}</div></div>}
      <div className="terminal-bar">
        <span className="glitch">GLOBAL COMPANY THREAT BUREAU — TOP 10 24/7</span>
        <span className="blink" style={{ color: 'var(--accent-green)' }}>LIVE TRACKING · {top.length} COMPANIES</span>
      </div>

      <div className="charts-row">
        <div className="chart-container" style={{ height: 160 }}>
          <div className="chart-title">COMPANY ATTACK STATS <span className="chart-badge">4s auto-refresh</span></div>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData.length > 0 ? barData : [{name:'...',threats:0,attacks:0}]}>
                <XAxis dataKey="name" tick={{fontSize:8,fill:'#94a3b8'}} />
                <YAxis tick={{fontSize:8,fill:'#94a3b8'}} />
                <Tooltip contentStyle={{background:'#1a2332',border:'1px solid #2d3a50',borderRadius:6,fontSize:10}} />
                <Bar dataKey="threats" fill="#ef4444" radius={[3,3,0,0]} name="Threats" />
                <Bar dataKey="attacks" fill="#f59e0b" radius={[3,3,0,0]} name="Attacks" />
                <Bar dataKey="breaches" fill="#8b5cf6" radius={[3,3,0,0]} name="Breaches" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="soc-stats" style={{marginBottom:8}}>
        <div className="soc-stat critical"><div className="soc-stat-val">{top.length}</div><div className="soc-stat-lbl">TRACKED</div></div>
        <div className="soc-stat high"><div className="soc-stat-val">{top.reduce((s,c)=>s+(c.threats||0),0)}</div><div className="soc-stat-lbl">TOTAL THREATS</div></div>
        <div className="soc-stat medium"><div className="soc-stat-val">{top.reduce((s,c)=>s+(c.attacks||0),0)}</div><div className="soc-stat-lbl">TOTAL ATTACKS</div></div>
        <div className="soc-stat low"><div className="soc-stat-val">{top.filter(c=>c.risk==='critical').length}</div><div className="soc-stat-lbl">CRITICAL</div></div>
      </div>

      <div style={{display:'flex',flexDirection:'column',gap:4}}>
        {top.map(c => {
          const risk = c.risk || 'low'
          const suspect = SUSPECTED_THREATS[(c.name||'').split(' ')[0]?.toLowerCase().replace(/[^a-z]/g,'')] || { likely: ['Data breach','Credential stuffing','Phishing'], target: 'General corporate infrastructure' }
          return (
            <div key={c.rank} className="soc-src-chip" style={{cursor:'pointer',flexDirection:'column',alignItems:'stretch',padding:'8px 12px',
              borderColor: RISK_COLORS[risk] || '#64748b',
              boxShadow: selected?.rank === c.rank ? `0 0 12px ${RISK_COLORS[risk]}40` : 'none' }}
              onClick={() => { const was = selected?.rank === c.rank; setSelected(was ? null : c); if (!was) saveCompanyClick(c) }}>
              <div style={{display:'flex',alignItems:'center',gap:8,width:'100%'}}>
                <span className="soc-src-id" style={{fontSize:10,minWidth:22}}>#{c.rank}</span>
                <span style={{fontWeight:700,fontSize:11}}>{c.name}</span>
                <span className={`soc-tag ${risk==='critical'?'cve':risk==='high'?'url':risk==='medium'?'ioc':'info'}`} style={{fontSize:7}}>{risk.toUpperCase()}</span>
                <span style={{fontSize:8,color:'var(--text-secondary)'}}>{c.sector}</span>
                <span style={{fontSize:8,color:'var(--accent-cyan)'}}>{c.market_cap}</span>
                <span style={{fontSize:8,color:'var(--text-secondary)'}}>{c.country}</span>
                <div style={{marginLeft:'auto',display:'flex',gap:12,fontSize:8}}>
                  <span style={{color:'var(--accent-red)'}}>⚠ {c.threats||0}</span>
                  <span style={{color:'var(--accent-yellow)'}}>⚔ {c.attacks||0}</span>
                  <span style={{color:'var(--accent-purple)'}}>🔓 {c.breaches||0}</span>
                  <span style={{color:'var(--accent-cyan)'}}>🔌 {c.ports||0}</span>
                </div>
              </div>
              <div style={{fontSize:8,color:'var(--text-secondary)',marginTop:4,display:'flex',gap:12}}>
                <span><strong>Ticker:</strong> {c.ticker}</span>
                <span><strong>CEO:</strong> {c.ceo}</span>
                <span><strong>Employees:</strong> {c.employees?.toLocaleString()}</span>
              </div>

              {selected?.rank === c.rank && (
                <div style={{marginTop:8,padding:'8px 10px',background:'var(--bg-tertiary)',borderRadius:6,border:'1px solid var(--border)',fontSize:9,lineHeight:1.6}}>
                  <div style={{display:'flex',gap:16,flexWrap:'wrap',marginBottom:6}}>
                    <div><strong style={{color:'var(--accent-cyan)'}}>Products:</strong> {c.products?.join(', ')||'—'}</div>
                    <div><strong style={{color:'var(--accent-cyan)'}}>CEO:</strong> {c.ceo}</div>
                    <div><strong style={{color:'var(--accent-cyan)'}}>Employees:</strong> {c.employees?.toLocaleString()}</div>
                  </div>
                  <div style={{marginBottom:4}}><strong style={{color:'var(--accent-red)'}}>⚠ SUSPECTED THREATS:</strong></div>
                  <ul style={{margin:0,paddingLeft:14,color:'var(--text-secondary)'}}>
                    {suspect.likely.map((s,i) => <li key={i}>{s}</li>)}
                  </ul>
                  <div style={{marginTop:4}}><strong style={{color:'var(--accent-cyan)'}}>Primary Target:</strong> <span style={{color:'var(--text-secondary)'}}>{suspect.target}</span></div>
                  <div style={{marginTop:6,display:'flex',gap:4}}>
                    <button className="btn btn-primary" style={{fontSize:8,padding:'3px 8px'}}
                      onClick={e=>{e.stopPropagation();onThreatClick?.({type:'company',name:c.name,risk,c,...c})}}>
                      VIEW THREATS
                    </button>
                    <button className="btn btn-primary" style={{fontSize:8,padding:'3px 8px',background:'var(--accent-purple)'}}
                      onClick={e=>{e.stopPropagation();fetch('/api/company-intel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({company:(c.name||'').split('(')[0].trim()})}).then(r=>r.json()).then(d=>onThreatClick?.({type:'company_recon',name:c.name,data:d}))}}>
                      DEEP RECON
                    </button>
                  </div>
                  <div style={{marginTop:4,height:4,background:'var(--bg-primary)',borderRadius:2,display:'flex',overflow:'hidden'}}>
                    <div style={{width:`${Math.min((c.threats||0)*3,100)}%`,background:'var(--accent-red)',height:'100%'}} title={`Threats: ${c.threats}`} />
                    <div style={{width:`${Math.min((c.attacks||0)*3,100)}%`,background:'var(--accent-yellow)',height:'100%'}} title={`Attacks: ${c.attacks}`} />
                    <div style={{width:`${Math.min((c.breaches||0)*5,100)}%`,background:'var(--accent-orange, #f97316)',height:'100%'}} title={`Breaches: ${c.breaches}`} />
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {top.length === 0 && (
        <div className="soc-panel"><div className="soc-empty">Loading top 10 company threat data — 24/7 tracking active...</div></div>
      )}

      {companyHistory.length > 0 && (
        <div className="soc-panel" style={{marginTop:10}}>
          <div className="soc-panel-header">
            YOUR COMPANY HISTORY — LOCAL <span className="soc-badge">{companyHistory.length} views</span>
            <button className="btn-icon" onClick={() => { setCompanyHistory([]); localStorage.removeItem('sys_company_history') }}
              style={{color:'var(--accent-red)',marginLeft:'auto',fontSize:9}}>CLEAR</button>
          </div>
          <div style={{display:'flex',flexDirection:'column',gap:2,maxHeight:120,overflow:'auto'}}>
            {companyHistory.slice(0,30).map((h,i) => (
              <div key={i} className="soc-src-chip" style={{padding:'3px 8px',fontSize:8,opacity:1-i*0.015}}>
                <span className="soc-src-id">{h.ticker}</span>
                <span style={{fontWeight:600}}>{h.name}</span>
                <span className={`soc-tag ${h.risk==='critical'?'cve':h.risk==='high'?'url':'info'}`} style={{fontSize:6}}>{h.risk}</span>
                <span className="soc-time">{new Date(h.t).toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
