import { useEffect, useState, type ReactNode } from 'react'
import type { Stats } from '../types'

interface Props {
  ready: boolean
  stats: Stats
}

const stages = [
  { key: 'discovery', icon: '🔍', label: 'Discovery', sub: (s: Stats) => `${s.totalTargets} NGOs found` },
  { key: 'fingerprint', icon: '🔬', label: 'Fingerprint', sub: (s: Stats) => `${s.totalTargets}/${s.totalTargets} vibe-coded` },
  { key: 'scan', icon: '🛡️', label: 'Scan', sub: (s: Stats) => `${s.totalVulnerabilities} findings` },
  { key: 'score', icon: '📊', label: 'Score', sub: (s: Stats) => `Avg ${s.averageVibeRiskScore}/100` },
  { key: 'report', icon: '📄', label: 'Report', sub: (s: Stats) => `${s.totalTargets} reports` },
]

export default function PipelineBar({ ready, stats }: Props) {
  const [completed, setCompleted] = useState<number>(-1)

  useEffect(() => {
    if (!ready) { setCompleted(-1); return }
    const timers: ReturnType<typeof setTimeout>[] = []
    stages.forEach((_, i) => {
      timers.push(setTimeout(() => setCompleted(i), i * 400 + 300))
    })
    return () => timers.forEach(clearTimeout)
  }, [ready])

  const items: ReactNode[] = []
  stages.forEach((stage, i) => {
    items.push(
      <div key={stage.key} className={`pipeline-stage ${i <= completed ? 'completed' : ''}`} data-stage={stage.key}>
        <div className="stage-icon">{stage.icon}</div>
        <div className="stage-label">{stage.label}</div>
        <div className="stage-sub">{stage.sub(stats)}</div>
      </div>
    )
    if (i < stages.length - 1) {
      items.push(
        <div key={`conn-${i}`} className={`pipeline-connector ${i < completed ? 'completed' : ''}`} />
      )
    }
  })

  return (
    <section id="pipeline-bar">
      <div className="pipeline-inner">
        {items}
      </div>
    </section>
  )
}
