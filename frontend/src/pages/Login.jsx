import { useState } from 'react'
import { useAuth } from '../lib/AuthContext.jsx'
import Aurora from '../components/bits/Aurora.jsx'
import SpotlightCard from '../components/bits/SpotlightCard.jsx'

export default function Login() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      await login(username, password)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-sunken relative overflow-hidden">
      <div className="absolute inset-0" aria-hidden="true">
        <Aurora speed={0.8} amplitude={1.1} />
      </div>
      <div className="absolute inset-0 bg-bg-sunken/60" aria-hidden="true" />
      <div className="relative w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="text-emerald-400 font-bold text-2xl tracking-[0.3em] glow-text">LOGSENTINEL</div>
          <div className="text-[11px] text-slate-500 tracking-wider mt-2">RAW LOGS IN · INTELLIGENCE OUT</div>
        </div>
        <SpotlightCard className="rounded-xl">
          <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="username" className="block text-[11px] tracking-widest text-slate-500 mb-1.5">USERNAME</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              autoFocus
              aria-required="true"
              className="w-full bg-slate-900/60 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </div>
          <div>
            <label htmlFor="password" className="block text-[11px] tracking-widest text-slate-500 mb-1.5">PASSWORD</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              aria-required="true"
              className="w-full bg-slate-900/60 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 transition-colors"
            />
          </div>
          {error && <div className="text-xs text-red-400 bg-red-500/10 rounded px-3 py-2">{error}</div>}
          <button
            type="submit"
            disabled={busy || !username || !password}
            className="w-full py-2.5 rounded text-sm tracking-wider font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30 shadow-[0_0_18px_rgba(16,185,129,0.25)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {busy ? 'AUTHENTICATING...' : 'SIGN IN'}
          </button>
        </form>
        </SpotlightCard>
        <div className="text-center mt-4 text-[10px] text-slate-400">
          Default credentials: admin / changeme
        </div>
      </div>
    </div>
  )
}
