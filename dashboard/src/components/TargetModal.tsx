import { useEffect } from 'react'
import type { Target } from '../types'
import { getScoreColor } from '../utils'

interface Props {
  target: Target
  onClose: () => void
}

export default function TargetModal({ target: t, onClose }: Props) {
  const scoreColor = getScoreColor(t.scoring.vibeRiskScore)
  const critCount = t.vulnerabilities.filter(v => v.severity === 'CRITICAL').length
  const highCount = t.vulnerabilities.filter(v => v.severity === 'HIGH').length

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handleKey)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', handleKey)
      document.body.style.overflow = ''
    }
  }, [onClose])

  return (
    <div className="modal-overlay active" onClick={e => { if (e.target === e.currentTarget) onClose() }}>
      <div className="modal">
        <button className="modal-close" onClick={onClose}>&times;</button>

        <div className="modal-target-header">
          <div>
            <div className="modal-target-name">{t.name}</div>
            <div className="modal-target-domain">{t.domain}</div>
            <span className={`target-sector ${t.sector}`} style={{ marginTop: 8, display: 'inline-block' }}>{t.sector}</span>
          </div>
          <div className="modal-score-display">
            <div className="modal-score-number" style={{ color: scoreColor }}>{t.scoring.vibeRiskScore}</div>
            <div className="modal-score-label">Vibe Risk Score</div>
          </div>
        </div>

        <div className="modal-section">
          <h4>📋 Mission</h4>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{t.mission}</p>
        </div>

        <div className="modal-section">
          <h4>⚡ Tech Stack</h4>
          <div className="target-stack">
            <span className="stack-tag">{t.techStack.platform}</span>
            <span className="stack-tag">{t.techStack.framework || 'Unknown'}</span>
            {t.techStack.isVibeCoded && (
              <span className="stack-tag" style={{ background: 'rgba(255, 97, 216, 0.12)', color: '#ff61d8', borderColor: 'rgba(255, 97, 216, 0.2)' }}>
                ⚡ vibe-coded
              </span>
            )}
          </div>
        </div>

        <div className="modal-section">
          <h4>🌐 Discovered Subdomains ({t.subdomains.length})</h4>
          <div className="modal-subdomains">
            {t.subdomains.map(s => <span key={s} className="subdomain-chip">{s}</span>)}
          </div>
        </div>

        <div className="modal-section">
          <h4>🔒 Security Headers ({t.securityHeaders.score ?? 'N/A'}%)</h4>
          <div className="modal-headers">
            {t.securityHeaders.missing.map(h => <span key={h} className="header-chip missing">✗ {h}</span>)}
            {t.securityHeaders.present.map(h => <span key={h} className="header-chip present">✓ {h}</span>)}
          </div>
        </div>

        <div className="modal-section">
          <h4>🐛 Vulnerabilities ({t.vulnerabilities.length}) — {critCount} Critical, {highCount} High</h4>
          <div className="modal-vuln-list">
            {t.vulnerabilities.map(v => (
              <div key={v.id} className={`modal-vuln ${v.severity}`}>
                <div className="modal-vuln-header">
                  <span className="modal-vuln-title">{v.title}</span>
                  <span className={`modal-vuln-severity ${v.severity}`}>{v.severity}</span>
                </div>
                <div className="modal-vuln-location">{v.id} · {v.category} · {v.cwe} · {v.location}</div>
              </div>
            ))}
          </div>
        </div>

        {t.scoring.criticalDataExposure && (
          <div className="modal-section" style={{ padding: 16, background: 'rgba(255, 59, 92, 0.06)', border: '1px solid rgba(255, 59, 92, 0.15)', borderRadius: 'var(--radius-md)' }}>
            <h4 style={{ color: 'var(--severity-critical)' }}>⚠️ Critical Data Exposure Detected</h4>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>This organization handles sensitive data (PII, minor data, or health records) that appears to be insufficiently protected based on the vulnerabilities found.</p>
          </div>
        )}
      </div>
    </div>
  )
}
