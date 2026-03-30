import { useMemo } from 'react'
import type { Target } from '../types'
import { getScoreColor } from '../utils'

interface Props {
  targets: Target[]
}

const dataTypes = [
  { icon: '👶', type: 'Protected Minor PII', detail: 'Child profiles, photos, welfare records', level: 'CRITICAL' },
  { icon: '📋', type: 'Case File Records', detail: 'Refugee status, legal cases, personal histories', level: 'CRITICAL' },
  { icon: '🏥', type: 'Health & Welfare', detail: 'Medical histories, disability status, trauma assessments', level: 'CRITICAL' },
  { icon: '📍', type: 'Location Data', detail: 'Refugee camps, aid distribution points, field worker locations', level: 'HIGH' },
  { icon: '💰', type: 'Financial Records', detail: 'Donor payment info, transaction histories', level: 'HIGH' },
  { icon: '🔵', type: 'Personal PII', detail: 'Names, emails, phone numbers, addresses', level: 'MEDIUM' },
]

export default function RiskMatrixPanel({ targets }: Props) {
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    for (const t of targets) {
      for (const v of t.vulnerabilities) {
        counts[v.severity] = (counts[v.severity] || 0) + 1
      }
    }
    return counts
  }, [targets])

  const stackCounts = useMemo(() => {
    const stacks: Record<string, number> = {}
    for (const t of targets) {
      const platform = t.techStack.platform || 'Unknown'
      stacks[platform] = (stacks[platform] || 0) + 1
    }
    return stacks
  }, [targets])

  const maxSeverity = Math.max(...Object.values(severityCounts), 1)
  const sorted = [...targets].sort((a, b) => b.scoring.vibeRiskScore - a.scoring.vibeRiskScore)

  return (
    <div className="risk-matrix-container">
      <div className="risk-chart-section">
        <h3>Vulnerability Distribution</h3>
        <div className="severity-chart">
          {Object.entries(severityCounts).map(([sev, count]) => (
            <div key={sev} className="severity-row">
              <div className="severity-label" style={{ color: `var(--severity-${sev.toLowerCase()})` }}>{sev}</div>
              <div className="severity-bar-track">
                <div className={`severity-bar-fill ${sev.toLowerCase()}`} style={{ width: `${(count / maxSeverity) * 100}%` }}>
                  <span className="severity-bar-count">{count}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="risk-chart-section">
        <h3>Risk Score Ranking</h3>
        <div className="risk-bars">
          {sorted.map(t => (
            <div key={t.domain} className="risk-bar-row">
              <div className="risk-bar-name">{t.name}</div>
              <div className="risk-bar-track">
                <div className="risk-bar-fill" style={{
                  width: `${t.scoring.vibeRiskScore}%`,
                  background: `linear-gradient(90deg, ${getScoreColor(t.scoring.vibeRiskScore)}88, ${getScoreColor(t.scoring.vibeRiskScore)})`,
                }}>
                  {t.scoring.vibeRiskScore}/100
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="risk-chart-section">
        <h3>Tech Stack Breakdown</h3>
        <div className="stack-chart">
          {Object.entries(stackCounts).map(([name, count]) => (
            <div key={name} className="stack-item">
              <div className="stack-count">{count}</div>
              <div className="stack-name">{name}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="risk-chart-section">
        <h3>Data Sensitivity Classification</h3>
        <div className="data-sensitivity">
          {dataTypes.map(d => (
            <div key={d.type} className="sensitivity-item">
              <div className="sensitivity-icon">{d.icon}</div>
              <div className="sensitivity-info">
                <div className="sensitivity-type">{d.type}</div>
                <div className="sensitivity-detail">{d.detail}</div>
              </div>
              <span className={`sensitivity-level ${d.level}`}>{d.level}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
