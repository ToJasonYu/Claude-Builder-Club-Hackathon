import { useState, useEffect, useCallback } from 'react'
import type { Target, TabId } from './types'
import Header from './components/Header'
import PipelineBar from './components/PipelineBar'
import StatsGrid from './components/StatsGrid'
import TabNav from './components/TabNav'
import TargetsPanel from './components/TargetsPanel'
import VulnerabilitiesPanel from './components/VulnerabilitiesPanel'
import RiskMatrixPanel from './components/RiskMatrixPanel'
import ReportPanel from './components/ReportPanel'
import TargetModal from './components/TargetModal'

export default function App() {
  const [targets, setTargets] = useState<Target[]>([])
  const [activeTab, setActiveTab] = useState<TabId>('targets')
  const [modalTarget, setModalTarget] = useState<Target | null>(null)
  const [scanning, setScanning] = useState(false)
  const [pipelineReady, setPipelineReady] = useState(false)

  const loadData = useCallback(async () => {
    try {
      const res = await fetch('/api/targets')
      const data: Target[] = await res.json()
      setTargets(data)
      setPipelineReady(false)
      setTimeout(() => setPipelineReady(true), 100)
    } catch (err) {
      console.error('Failed to load data:', err)
    }
  }, [])

  useEffect(() => { loadData() }, [loadData])

  const handleRunPipeline = async () => {
    setScanning(true)
    setPipelineReady(false)
    await new Promise(r => setTimeout(r, 2500))
    await loadData()
    setScanning(false)
  }

  const stats = {
    totalTargets: targets.length,
    totalVulnerabilities: targets.reduce((s, t) => s + t.vulnerabilities.length, 0),
    criticalFindings: targets.reduce((s, t) => s + t.vulnerabilities.filter(v => v.severity === 'CRITICAL').length, 0),
    highFindings: targets.reduce((s, t) => s + t.vulnerabilities.filter(v => v.severity === 'HIGH').length, 0),
    averageVibeRiskScore: targets.length ? Math.round(targets.reduce((s, t) => s + t.scoring.vibeRiskScore, 0) / targets.length) : 0,
    criticalDataTargets: targets.filter(t => t.scoring.criticalDataExposure).length,
  }

  return (
    <>
      <div className="bg-grid" />
      <div className="bg-glow bg-glow-1" />
      <div className="bg-glow bg-glow-2" />
      <div className="bg-glow bg-glow-3" />
      <div className="scan-line" />

      <Header scanning={scanning} onRunPipeline={handleRunPipeline} />
      <PipelineBar ready={pipelineReady} stats={stats} />

      <main>
        <StatsGrid stats={stats} />
        <TabNav activeTab={activeTab} onTabChange={setActiveTab} />

        <section id="tab-content">
          {activeTab === 'targets' && (
            <div className="tab-panel active">
              <TargetsPanel targets={targets} onViewTarget={setModalTarget} />
            </div>
          )}
          {activeTab === 'vulnerabilities' && (
            <div className="tab-panel active">
              <VulnerabilitiesPanel targets={targets} />
            </div>
          )}
          {activeTab === 'risk-map' && (
            <div className="tab-panel active">
              <RiskMatrixPanel targets={targets} />
            </div>
          )}
          {activeTab === 'report' && (
            <div className="tab-panel active">
              <ReportPanel targets={targets} />
            </div>
          )}
        </section>
      </main>

      {modalTarget && <TargetModal target={modalTarget} onClose={() => setModalTarget(null)} />}

      <footer>
        <div className="footer-inner">
          <p>🛡️ NGO-Guardian v1.0 — "We are Guardians, not Hunters."</p>
          <p className="footer-sub">Zero-exploitation · Privacy-first · Empathy always</p>
        </div>
      </footer>
    </>
  )
}
