import { useState, useEffect } from 'react'

export default function ScraperPanel() {
  const [threats, setThreats] = useState([])
  const [loading, setLoading] = useState(false)
  const [scraping, setScraping] = useState(false)
  const [message, setMessage] = useState('')

  const fetchThreats = () => {
    setLoading(true)
    fetch('/api/threats?limit=100')
      .then(r => r.json())
      .then(setThreats)
      .catch(() => setMessage('Failed to load threats'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchThreats() }, [])

  const triggerScrape = async () => {
    setScraping(true)
    setMessage('')
    try {
      const r = await fetch('/api/scrape')
      const d = await r.json()
      setMessage(`${d.message}`)
      fetchThreats()
    } catch { setMessage('Scrape failed') }
    finally { setScraping(false) }
  }

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>Threat Intelligence Scraper</h1>
      <div className="panel">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <p style={{ color: 'var(--text-secondary)' }}>
            Scrapes NVD, ThreatFox, AlienVault OTX, and URLhaus for cyber threat data.
          </p>
          <button className="btn btn-primary" onClick={triggerScrape} disabled={scraping}>
            {scraping ? 'Scraping...' : 'Scrape Now'}
          </button>
        </div>
        {message && <p style={{ color: 'var(--accent-green)', marginBottom: 12, fontSize: 14 }}>{message}</p>}
      </div>

      <div className="panel">
        <h2>Scraped Threats <span className="badge">{threats.length} entries</span></h2>
        {loading ? (
          <div className="loading"><div className="spinner" /> Loading...</div>
        ) : threats.length > 0 ? (
          <div className="threat-table">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Type</th>
                  <th>Instruction / Description</th>
                  <th>Source</th>
                  <th>Score</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((t, i) => (
                  <tr key={i}>
                    <td style={{ color: 'var(--text-secondary)' }}>{i + 1}</td>
                    <td><span className={`tag tag-${t.type === 'cve' ? 'cve' : 'ioc'}`}>{t.type || 'threat'}</span></td>
                    <td style={{ maxWidth: 400 }}>{t.instruction?.slice(0, 120) || t.description?.slice(0, 120) || '-'}</td>
                    <td>{t.source || '-'}</td>
                    <td>{t.cvss_score || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="loading"><div className="spinner" /> Click 'Scrape Now' to collect threat data</div>
        )}
      </div>
    </div>
  )
}
