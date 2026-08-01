import { ShieldCheck } from 'lucide-react'

import './app.css'

export function App() {
  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-icon" aria-hidden="true">
          <ShieldCheck size={20} strokeWidth={1.8} />
        </div>
        <div>
          <h1>N-API-P</h1>
          <p>Administration</p>
        </div>
      </header>
      <main className="workspace" aria-label="Administration workspace" />
    </div>
  )
}
