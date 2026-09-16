import { useCallback, useEffect, useState } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import { api, classNames } from '../lib/api.js'
import { hasRole, useRole } from '../lib/AuthContext.jsx'

const CATEGORIES = ['EMAIL', 'PHONE', 'PASSWORD', 'API_KEY', 'TOKEN',
    'SESSION_ID', 'ACCOUNT_NUMBER', 'EMPLOYEE_ID', 'NAME']
const ACTIONS = ['REDACT', 'TYPE', 'MASK', 'HASH', 'KEEP']

const ACTION_HINT = {
    REDACT: '[EMAIL_REDACTED]',
    TYPE: '[EMAIL]',
    MASK: 'am****@e****.com',
    HASH: '[EMAIL:a1b2c3…] (correlatable)',
    KEEP: 'unchanged',
}

export default function Privacy() {
    const [policy, setPolicy] = useState({})
    const [saved, setSaved] = useState(false)
    const [error, setError] = useState('')
    const canEdit = hasRole('admin', useRole())

    useEffect(() => {
        api('/policy').then((d) => setPolicy(d.policy)).catch((e) => setError(String(e.message || e)))
    }, [])

    const save = useCallback(async () => {
        setSaved(false); setError('')
        try {
            const d = await api('/policy', { method: 'PUT', body: JSON.stringify({ policy }) })
            setPolicy(d.policy); setSaved(true)
            setTimeout(() => setSaved(false), 2500)
        } catch (e) { setError(String(e.message || e)) }
    }, [policy])

    return (
        <div className="p-4 md:p-6 lg:p-8 max-w-3xl">
            <PageHeader title="PRIVACY POLICY ENGINE" subtitle="Controls how each sensitive category leaves this system. Applied at every output surface (API responses · exports · reports · graph · search). IPs are security indicators by default and are governed separately." />

            <div className="border border-slate-800 rounded overflow-hidden">
                <table className="w-full text-xs">
                    <thead className="bg-slate-900/80 text-slate-500 tracking-wider">
                        <tr>
                            <th className="px-4 py-2 text-left font-normal">CATEGORY</th>
                            <th className="px-4 py-2 text-left font-normal">ACTION</th>
                            <th className="px-4 py-2 text-left font-normal">EXAMPLE OUTPUT</th>
                        </tr>
                    </thead>
                    <tbody>
                        {CATEGORIES.map((cat) => (
                            <tr key={cat} className="border-t border-slate-800/60">
                                <td className="px-4 py-2 text-slate-200 font-bold">{cat}</td>
                                <td className="px-4 py-2">
                                    <select value={policy[cat] || 'REDACT'}
                                            onChange={(e) => setPolicy({ ...policy, [cat]: e.target.value })}
                                            aria-label={`Privacy action for ${cat}`}
                                            disabled={!canEdit}
                                            title={canEdit ? undefined : 'requires admin'}
                                            className="bg-slate-950 border border-slate-700 rounded px-2 py-1 focus:outline-none focus:border-emerald-600 disabled:cursor-not-allowed disabled:opacity-50">
                                        {ACTIONS.map((a) => <option key={a}>{a}</option>)}
                                    </select>
                                </td>
                                <td className={classNames('px-4 py-2 font-mono text-[11px]',
                                    policy[cat] === 'KEEP' ? 'text-orange-300' : 'text-emerald-300')}>
                                    {ACTION_HINT[policy[cat]] || ''}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <div className="mt-4 flex items-center gap-3">
                <button onClick={save} disabled={!canEdit}
                        title={canEdit ? undefined : 'requires admin'}
                        className="btn btn-primary px-6 py-2 disabled:cursor-not-allowed disabled:opacity-40">
                    SAVE POLICY
                </button>
                {saved && <span className="text-xs text-emerald-400">✓ saved & hot-reloaded</span>}
            </div>
            {!canEdit && (
                <div className="mt-2 text-[11px] text-amber-400/80">Read-only for your role. Saving requires the admin role.</div>
            )}
            {error && <div className="mt-3 text-sm text-red-400">{error}</div>}
        </div>
    )
}
