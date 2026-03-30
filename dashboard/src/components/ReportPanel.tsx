import { useState, useMemo } from 'react'
import type { Target } from '../types'
import { renderMarkdown } from '../utils'

interface Props {
  targets: Target[]
}

interface ReportItem {
  name: string
  type: string
  endpoint: string
}

export default function ReportPanel({ targets }: Props) {
  const [activeReport, setActiveReport] = useState<string | null>(null)
  const [reportContent, setReportContent] = useState<string>('')
  const [loading, setLoading] = useState(false)

  const reports = useMemo<ReportItem[]>(() => [
    { name: 'Full Vibe Check Report', type: 'vibe-check-report.md', endpoint: '/api/report' },
    { name: 'Fix Artifact (Patches)', type: 'fix-artifact.patch', endpoint: '/api/fix-artifact' },
    ...targets.map(t => ({
      name: t.name,
      type: `findings/${t.domain.replace(/\./g, '-')}.md`,
      endpoint: `/api/findings/${t.domain.replace(/\./g, '-')}`,
    })),
  ], [targets])

  const handleLoadReport = async (endpoint: string) => {
    setActiveReport(endpoint)
    setLoading(true)
    try {
      const res = await fetch(endpoint)
      const text = await res.text()
      setReportContent(renderMarkdown(text))
    } catch {
      setReportContent('<p class="report-placeholder">Failed to load report.</p>')
    }
    setLoading(false)
  }

  return (
    <div className="report-viewer">
      <div className="report-sidebar">
        <h3>Generated Reports</h3>
        <div className="report-list">
          {reports.map(r => (
            <div
              key={r.endpoint}
              className={`report-list-item ${activeReport === r.endpoint ? 'active' : ''}`}
              onClick={() => handleLoadReport(r.endpoint)}
            >
              <div className="report-item-name">{r.name}</div>
              <div className="report-item-type">{r.type}</div>
            </div>
          ))}
        </div>
      </div>
      <div className="report-content">
        <div className="report-display">
          {!activeReport && <p className="report-placeholder">Select a report from the sidebar to view its contents.</p>}
          {loading && <p className="report-placeholder">Loading...</p>}
          {activeReport && !loading && <div dangerouslySetInnerHTML={{ __html: reportContent }} />}
        </div>
      </div>
    </div>
  )
}
