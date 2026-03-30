interface Props {
  scanning: boolean
  onRunPipeline: () => void
}

export default function Header({ scanning, onRunPipeline }: Props) {
  return (
    <header id="site-header">
      <div className="header-inner">
        <div className="logo-group">
          <div className="logo-icon">
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
              <path d="M16 2L28 8V16C28 22.627 22.627 28 16 28C9.373 28 4 22.627 4 16V8L16 2Z" stroke="url(#logoGrad)" strokeWidth="2" fill="none"/>
              <path d="M16 8L22 11V16C22 19.314 19.314 22 16 22C12.686 22 10 19.314 10 16V11L16 8Z" fill="url(#logoGrad)" opacity="0.3"/>
              <path d="M14 16L15.5 17.5L19 14" stroke="url(#logoGrad)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              <defs><linearGradient id="logoGrad" x1="4" y1="2" x2="28" y2="28"><stop stopColor="#00f0ff"/><stop offset="1" stopColor="#7b61ff"/></linearGradient></defs>
            </svg>
          </div>
          <div>
            <h1 className="logo-text">NGO-GUARDIAN</h1>
            <p className="logo-sub">Autonomous Safety Net for Non-Profits</p>
          </div>
        </div>
        <div className="header-actions">
          <div className="status-badge live">
            <span className="pulse-dot" />
            LIVE SCAN
          </div>
          <button id="btn-run-scan" className="btn btn-primary" onClick={onRunPipeline} disabled={scanning}>
            {scanning ? (
              <><span className="pulse-dot" /> Scanning...</>
            ) : (
              <><svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M4 2L14 8L4 14V2Z" fill="currentColor"/></svg> Run Pipeline</>
            )}
          </button>
        </div>
      </div>
    </header>
  )
}
