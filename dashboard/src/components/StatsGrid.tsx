import { useEffect, useRef } from 'react'
import type { Stats } from '../types'

interface Props {
  stats: Stats
}

function AnimatedNumber({ target, suffix = '' }: { target: number; suffix?: string }) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!ref.current) return
    let current = 0
    const duration = 1200
    const step = target / (duration / 16)
    const timer = setInterval(() => {
      current += step
      if (current >= target) {
        current = target
        clearInterval(timer)
      }
      if (ref.current) {
        ref.current.innerHTML = Math.round(current) + (suffix ? `<span class="stat-unit">${suffix}</span>` : '')
      }
    }, 16)
    return () => clearInterval(timer)
  }, [target, suffix])

  return <div className="stat-value" ref={ref}>0</div>
}

const cards = [
  { key: 'targets', icon: '🎯', cls: 'stat-targets', label: 'NGOs Scanned', detail: '.org domains', getValue: (s: Stats) => s.totalTargets },
  { key: 'vulns', icon: '🐛', cls: 'stat-vulns', label: 'Vulnerabilities', detail: 'detected', getValue: (s: Stats) => s.totalVulnerabilities },
  { key: 'critical', icon: '🔴', cls: 'stat-critical', label: 'Critical', detail: 'require immediate action', getValue: (s: Stats) => s.criticalFindings },
  { key: 'score', icon: '📊', cls: 'stat-score', label: 'Avg Risk Score', detail: 'Vibe Risk Index', getValue: (s: Stats) => s.averageVibeRiskScore, suffix: '/100' },
  { key: 'data', icon: '⚠️', cls: 'stat-data', label: 'Critical Data', detail: 'PII exposure detected', getValue: (s: Stats) => s.criticalDataTargets },
]

export default function StatsGrid({ stats }: Props) {
  return (
    <section id="stats-section">
      <div className="stats-grid">
        {cards.map(card => (
          <div key={card.key} className={`stat-card ${card.cls}`}>
            <div className="stat-icon">{card.icon}</div>
            <AnimatedNumber target={card.getValue(stats)} suffix={card.suffix} />
            <div className="stat-label">{card.label}</div>
            <div className="stat-detail">{card.detail}</div>
          </div>
        ))}
      </div>
    </section>
  )
}
