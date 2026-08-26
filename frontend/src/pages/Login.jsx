import { useState } from 'react'
import { useAuth } from '../lib/AuthContext.jsx'

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
    <div className="min-h-screen flex items-center justify-center bg-bg-sunken">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="text-emerald-400 font-bold text-2xl tracking-[0.3em]">LOGSENTINEL</div>
          <div className="text-[11px] text-slate-500 tracking-wider mt-2">RAW LOGS IN · INTELLIGENCE OUT</div>
        </div>
        <form onSubmit={handleSubmit} className="bg-bg-surface border border-slate-700 rounded-xl p-6 space-y-4">
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
            className="w-full py-2.5 rounded text-sm tracking-wider font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {busy ? 'AUTHENTICATING...' : 'SIGN IN'}
          </button>
        </form>
        <div className="text-center mt-4 text-[10px] text-slate-600">
          Default credentials: admin / changeme
        </div>
      </div>
    </div>
  )
}
