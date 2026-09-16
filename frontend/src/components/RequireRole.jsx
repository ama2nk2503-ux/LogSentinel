import { Outlet } from 'react-router-dom'
import { useAuth, hasRole } from '../lib/AuthContext.jsx'

export default function RequireRole({ minRole = 'analyst', children }) {
  const { user } = useAuth()
  const allowed = hasRole(minRole, user?.role)

  if (allowed) return children || <Outlet />
  return (
    <div className="p-4 md:p-6 lg:p-8">
      <div className="border border-amber-800 rounded-lg p-6 max-w-xl bg-amber-950/10">
        <div className="text-xs tracking-widest text-amber-400 font-bold">ACCESS RESTRICTED</div>
        <div className="mt-2 text-sm text-slate-300">
          This area requires role <span className="text-emerald-300 font-bold">{minRole.toUpperCase()}</span>{' '}
          or above. Your account is <span className="text-emerald-300 font-bold">{(user?.role || 'viewer').toUpperCase()}</span>.
        </div>
        <div className="mt-1 text-[11px] text-slate-500">
          Ask an administrator to elevate your role if this was unexpected.
        </div>
      </div>
    </div>
  )
}