import { useState, useEffect } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import {
  Activity,
  Bell,
  Boxes,
  Clapperboard,
  Download,
  FileText,
  FlaskConical,
  Gauge,
  Globe,
  TrendingUp,
  Lock,
  Network,
  RadioTower,
  Scale,
  ScrollText,
  Server,
  Shield,
  ShieldAlert,
  MessagesSquare,
  Upload,
  Users,
} from 'lucide-react'
import { useAuth, useRole, hasRole } from '../lib/AuthContext.jsx'
import GlitchText from './bits/GlitchText.jsx'

const links = [
  { to: '/', label: 'UPLOAD', end: true, icon: Upload, minRole: 'analyst' },
  { to: '/demo', label: '★ DEMO MODE', icon: Clapperboard, minRole: 'analyst' },
  { to: '/dashboard', label: 'DASHBOARD', icon: Gauge, minRole: 'viewer' },
  { to: '/explorer', label: 'LOG EXPLORER', icon: ScrollText, minRole: 'viewer' },
  { to: '/threats', label: 'THREATS', icon: ShieldAlert, minRole: 'viewer' },
  { to: '/alerts', label: 'ALERTS', icon: Bell, minRole: 'viewer' },
  { to: '/live', label: 'EVENT WALL', icon: RadioTower, minRole: 'viewer' },
  { to: '/graph', label: 'ATTACK GRAPH', icon: Network, minRole: 'viewer' },
  { to: '/intel', label: 'INTEL', icon: Globe, minRole: 'viewer' },
  { to: '/baseline', label: 'ENTITY BASELINE', icon: TrendingUp, minRole: 'viewer' },
  { to: '/compliance', label: 'COMPLIANCE', icon: Scale, minRole: 'viewer' },
  { to: '/assets', label: 'ASSET INVENTORY', icon: Server, minRole: 'viewer' },
  { to: '/privacy', label: 'PRIVACY', icon: Lock, minRole: 'viewer' },
  { to: '/export', label: 'EXPORT', icon: Download, minRole: 'viewer' },
  { to: '/benchmark', label: 'BENCHMARK', icon: Activity, minRole: 'analyst' },
  { to: '/schema-docs', label: 'SCHEMA DOCS', icon: FileText, minRole: 'viewer' },
  { to: '/parser-lab', label: 'PARSER LAB', icon: FlaskConical, minRole: 'analyst' },
  { to: '/assistant', label: 'AI ASSISTANT', icon: MessagesSquare, minRole: 'analyst' },
  { to: '/modes', label: 'MODES', icon: Boxes, minRole: 'analyst' },
  { to: '/users', label: 'USER MANAGEMENT', icon: Users, minRole: 'admin' },
]

export default function Layout() {
  const { user, logout } = useAuth()
  const role = useRole()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const location = useLocation()

  useEffect(() => { setSidebarOpen(false) }, [location.pathname])

  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') setSidebarOpen(false) }
    if (sidebarOpen) window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [sidebarOpen])

  return (
    <div className="flex h-screen overflow-hidden">
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside className={`
        fixed inset-y-0 left-0 z-40 w-56 bg-bg-surface border-r border-slate-700 flex flex-col
        transition-transform duration-200 ease-in-out
        lg:static lg:translate-x-0 lg:shrink-0
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        <div className="px-5 py-5 border-b border-slate-700">
          <div className="flex items-center gap-2 text-emerald-400">
            <Shield size={18} strokeWidth={2} />
            <GlitchText speed={0.9} enableOnHover className="font-bold text-lg tracking-widest glow-text">
              LOGSENTINEL
            </GlitchText>
          </div>
          <div className="text-[10px] text-text-muted tracking-wider mt-1.5">RAW LOGS IN · INTELLIGENCE OUT</div>
        </div>
        <nav className="flex-1 py-3 overflow-y-auto" aria-label="Main navigation">
          {links.filter((l) => hasRole(l.minRole ?? 'viewer', role)).map((l) => {
            const Icon = l.icon
            return (
              <NavLink
                key={l.to}
                to={l.to}
                end={l.end}
                aria-current={({ isActive }) => (isActive ? 'page' : undefined)}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-4 py-2.5 text-xs tracking-wider transition-colors ${
                    isActive
                      ? 'text-emerald-300 bg-emerald-500/10 border-r-2 border-emerald-400'
                      : 'text-text-secondary hover:text-text-primary hover:bg-slate-700/40'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <Icon
                      size={15}
                      strokeWidth={1.75}
                      className={isActive ? 'text-emerald-400 drop-shadow-[0_0_6px_rgba(52,211,153,0.6)]' : 'opacity-70'}
                    />
                    <span>{l.label}</span>
                  </>
                )}
              </NavLink>
            )
          })}
        </nav>
        <div className="px-5 py-4 border-t border-slate-700 flex items-center justify-between">
          <div className="text-[10px] text-text-muted">SIH26156 · v0.1.0</div>
          {user && (
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-text-secondary">
                {user.username}
                <span className="ml-1.5 px-1 py-0.5 border border-slate-700 rounded text-[9px] text-emerald-400">
                  {role.toUpperCase()}
                </span>
              </span>
              <button
                onClick={logout}
                className="text-[10px] text-text-secondary hover:text-red-400 transition-colors"
                title="Sign out"
              >
                SIGN OUT
              </button>
            </div>
          )}
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="lg:hidden flex items-center px-4 py-3 border-b border-slate-700 bg-bg-surface">
          <button
            onClick={() => setSidebarOpen(true)}
            className="p-1.5 rounded hover:bg-slate-700/40 text-text-secondary"
            aria-label="Open menu"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <span className="ml-3 flex items-center gap-2 text-emerald-400 font-bold text-sm tracking-widest">
            <Shield size={15} strokeWidth={2} />
            LOGSENTINEL
          </span>
        </header>

        <main className="flex-1 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  )
}