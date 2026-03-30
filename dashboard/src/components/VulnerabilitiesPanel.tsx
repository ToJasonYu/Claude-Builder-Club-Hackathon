import { useState, useMemo } from 'react'
import type { Target, SeverityFilter, Vulnerability } from '../types'

interface Props {
  targets: Target[]
}

interface VulnWithOrg extends Vulnerability {
  org: string
  domain: string
}

export default function VulnerabilitiesPanel({ targets }: Props) {
  const [filter, setFilter] = useState<SeverityFilter>('all')

  const allVulns = useMemo(() => {
    const list: VulnWithOrg[] = []
    for (const t of targets) {
      for (const v of t.vulnerabilities) {
        list.push({ ...v, org: t.name, domain: t.domain })
      }
    }
    const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
    list.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4))
    return list
  }, [targets])

  const filtered = filter === 'all' ? allVulns : allVulns.filter(v => v.severity === filter)

  const filters: { label: string; value: SeverityFilter; cls?: string }[] = [
    { label: 'All', value: 'all' },
    { label: 'Critical', value: 'CRITICAL', cls: 'critical' },
    { label: 'High', value: 'HIGH', cls: 'high' },
    { label: 'Medium', value: 'MEDIUM', cls: 'medium' },
    { label: 'Low', value: 'LOW', cls: 'low' },
  ]

  return (
    <>
      <div className="vuln-controls">
        <div className="vuln-filters">
          {filters.map(f => (
            <button
              key={f.value}
              className={`filter-btn ${f.cls || ''} ${filter === f.value ? 'active' : ''}`}
              onClick={() => setFilter(f.value)}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>
      <div className="vuln-list">
        {filtered.map((v, i) => (
          <div key={`${v.org}-${v.id}-${i}`} className="vuln-item animate-in" style={{ animationDelay: `${i * 50}ms` }}>
            <div className={`vuln-severity-bar ${v.severity}`} />
            <div className="vuln-id">{v.id}</div>
            <div>
              <div className="vuln-title">{v.title}</div>
              <div className="vuln-location" title={v.location}>{v.org} — {v.location}</div>
            </div>
            <div className="vuln-category-tag">{v.category}</div>
            <div className={`vuln-badge ${v.severity.toLowerCase()}`} style={{ justifyContent: 'center' }}>{v.severity}</div>
          </div>
        ))}
      </div>
    </>
  )
}
