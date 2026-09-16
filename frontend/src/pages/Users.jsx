import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import PageHeader from '../components/PageHeader.jsx'
import Skeleton from '../components/Skeleton.jsx'
import { useAuth, useRole } from '../lib/AuthContext.jsx'
import { api, classNames } from '../lib/api.js'

const ROLES = ['viewer', 'analyst', 'admin']

export default function Users() {
  const queryClient = useQueryClient()
  const { user } = useAuth()
  const role = useRole()

  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'analyst' })

  const { data } = useQuery({
    queryKey: ['users'],
    queryFn: () => api('/auth/users').then((d) => d.users),
  })

  const changeRole = useMutation({
    mutationFn: ({ id, role }) =>
      api(`/auth/users/${id}`, { method: 'PATCH', body: JSON.stringify({ role }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
  })

  const createUser = useMutation({
    mutationFn: () =>
      api('/auth/users', { method: 'POST', body: JSON.stringify(newUser) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setNewUser({ username: '', password: '', role: 'analyst' })
    },
  })

  return (
    <div className="p-4 md:p-6 lg:p-8">
      <PageHeader title="USER MANAGEMENT" subtitle="Admin-only account lifecycle. Viewer = read-only; Analyst = analyst+; Admin = policy, alert-rule and user management." />

      {role === 'admin' && (
        <div className="border border-slate-800 rounded-lg mb-4">
          <div className="px-4 py-2 border-b border-slate-800/70 bg-slate-950/40">
            <span className="text-[10px] tracking-widest text-slate-500">CREATE ACCOUNT</span>
          </div>
          <form
            className="p-4 flex flex-wrap items-end gap-3"
            onSubmit={(e) => { e.preventDefault(); createUser.mutate() }}>
            <div className="min-w-[180px] flex-1">
              <label htmlFor="new-username" className="block text-[11px] tracking-widest text-slate-500 mb-1.5">USERNAME</label>
              <input id="new-username" className="input w-full" placeholder="e.g. analyst.one"
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} />
            </div>
            <div className="min-w-[180px] flex-1">
              <label htmlFor="new-password" className="block text-[11px] tracking-widest text-slate-500 mb-1.5">PASSWORD</label>
              <input id="new-password" type="password" className="input w-full" placeholder="minimum effort, maximum chaos"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
            </div>
            <div className="min-w-[140px]">
              <label htmlFor="new-role" className="block text-[11px] tracking-widest text-slate-500 mb-1.5">ROLE</label>
              <select id="new-role" className="input w-full"
                value={newUser.role}
                onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}>
                {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
            <button type="submit"
              disabled={createUser.isPending || !newUser.username || !newUser.password}
              className="py-2 px-4 rounded text-xs tracking-wider font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30 shadow-[0_0_18px_rgba(16,185,129,0.25)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
              {createUser.isPending ? 'CREATING...' : 'CREATE'}
            </button>
          </form>
          {createUser.isError && (
            <div className="mx-4 mb-3 text-[11px] text-red-400 bg-red-500/10 rounded px-3 py-2">
              {createUser.error?.message || 'Could not create account'}
            </div>
          )}
          {createUser.isSuccess && (
            <div className="mx-4 mb-3 text-[11px] text-emerald-400 bg-emerald-500/10 rounded px-3 py-2">
              Account created — the new user can sign in immediately.
            </div>
          )}
        </div>
      )}

      <div className="border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-4 py-2 flex items-center justify-between border-b border-slate-800/70 bg-slate-950/40">
          <span className="text-[10px] tracking-widest text-slate-500">ACCOUNTS</span>
          <span className="text-[10px] text-slate-500">signed in as {user?.username} ({role})</span>
        </div>
        {!data && <Skeleton rows={4} className="m-2" />}
        {data && (
          <table className="w-full text-xs" aria-label="User accounts">
            <thead>
              <tr>{['USERNAME', 'ROLE', 'CREATED', 'ACTION'].map((h) => (
                <th key={h} className="table-header">{h}</th>))}</tr>
            </thead>
            <tbody>
              {data.map((u) => (
                <tr key={u.id} className="border-t border-slate-800/60">
                  <td className="table-cell font-mono text-purple-300">{u.username}
                    {u.id === user?.id && <span className="ml-2 text-[10px] text-slate-500">(you)</span>}
                  </td>
                  <td className="table-cell">
                    <span className={classNames('px-1.5 py-0.5 border rounded text-[10px] font-bold',
                      u.role === 'admin' ? 'text-red-300 border-red-800'
                        : u.role === 'analyst' ? 'text-emerald-300 border-emerald-800'
                        : 'text-slate-400 border-slate-700')}>
                      {u.role.toUpperCase()}
                    </span>
                  </td>
                  <td className="table-cell text-slate-400">{(u.created_at || '').replace('T', ' ').slice(0, 19)}</td>
                  <td className="table-cell">
                    <select
                      value={u.role}
                      disabled={u.id === user?.id || changeRole.isPending}
                      onChange={(e) => changeRole.mutate({ id: u.id, role: e.target.value })}
                      aria-label={`Role for ${u.username}`}
                      title={u.id === user?.id ? 'Cannot change your own role' : undefined}
                      className="input w-28">
                      {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {data && data.length === 0 && (
        <div className="mt-3 text-sm text-emerald-500">No accounts yet. The default admin is seeded on first start.</div>
      )}
    </div>
  )
}