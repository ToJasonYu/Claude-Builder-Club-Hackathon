import type { Target } from '../types'
import { getScoreColor } from '../utils'

interface Props {
  targets: Target[]
  onViewTarget: (target: Target) => void
}

export default function TargetsPanel({ targets, onViewTarget }: Props) {
  return (
    <div className="targets-grid">
      {targets.map((t, i) => {
        const critCount = t.vulnerabilities.filter(v => v.severity === 'CRITICAL').length
        const highCount = t.vulnerabilities.filter(v => v.severity === 'HIGH').length
        const medCount = t.vulnerabilities.filter(v => v.severity === 'MEDIUM').length
        const lowCount = t.vulnerabilities.filter(v => v.severity === 'LOW').length
        const scoreColor = getScoreColor(t.scoring.vibeRiskScore)
        const circumference = 2 * Math.PI * 26
        const offset = circumference - (t.scoring.vibeRiskScore / 100) * circumference

        return (
          <div key={t.domain} className="target-card animate-in" style={{ animationDelay: `${i * 100}ms` }}>
            <div className="target-card-header">
              <div className="target-info">
                <h3>{t.name}</h3>
                <div className="target-domain">{t.domain}</div>
                <span className={`target-sector ${t.sector}`}>{t.sector}</span>
              </div>
              <div className="target-score">
                <div className="score-ring">
                  <svg viewBox="0 0 64 64">
                    <circle className="score-ring-bg" cx="32" cy="32" r="26" />
                    <circle
                      className="score-ring-fill" cx="32" cy="32" r="26"
                      stroke={scoreColor}
                      strokeDasharray={circumference}
                      strokeDashoffset={offset}
                    />
                  </svg>
                  <div className="score-ring-value" style={{ color: scoreColor }}>{t.scoring.vibeRiskScore}</div>
                </div>
              </div>
            </div>
            <div className="target-card-body">
              <p className="target-mission">{t.mission}</p>
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
            <div className="target-card-footer">
              <div className="vuln-badges">
                {critCount > 0 && <span className="vuln-badge critical">{critCount} C</span>}
                {highCount > 0 && <span className="vuln-badge high">{highCount} H</span>}
                {medCount > 0 && <span className="vuln-badge medium">{medCount} M</span>}
                {lowCount > 0 && <span className="vuln-badge low">{lowCount} L</span>}
              </div>
              <button className="target-view-btn" onClick={() => onViewTarget(t)}>
                View Details →
              </button>
            </div>
          </div>
        )
      })}
    </div>
  )
}
