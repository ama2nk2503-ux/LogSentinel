import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import PageHeader from '../components/PageHeader.jsx'
import Skeleton from '../components/Skeleton.jsx'
import { api } from '../lib/api.js'

const CRIT_COLOR = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' }
const TYPE_COLOR = { web: '#818cf8', database: '#f472b6', server: '#38bdf8', network: '#34d399', unknown: '#64748b' }

export default function Assets() {
    const [jobId, setJobId] = useState('')

    const { data } = useQuery({
        queryKey: ['assets', jobId],
        queryFn: () => api(`/assets/${jobId}`),
        enabled: !!jobId,
    })

    return (
        <div className="p-4 md:p-6 lg:p-8">
            <PageHeader title="ASSET INVENTORY" />
            <div className="mb-5"><JobPicker value={jobId} onChange={setJobId} /></div>
            {!jobId && <div className="text-sm text-slate-500">Select a processed dataset to map its assets.</div>}

            {jobId && !data && <Skeleton rows={8} className="mt-4" />}

            {data && (
                <>
                    <div className="flex flex-wrap items-center gap-3 mb-5 text-[12px]">
                        <span className="text-slate-300 font-bold text-xs tracking-widest glow-text">{data.total} ASSETS</span>
                        {Object.entries(data.by_criticality).map(([c, n]) => (
                            <span key={c} className="flex items-center gap-1" style={{ color: CRIT_COLOR[c] }}>
                                <b>{n}</b> {c}
                            </span>
                        ))}
                        <span className="flex items-center gap-1 text-red-400 font-bold">
                            {data.critical_count} HIGH+ RISK
                        </span>
                    </div>

                    <div className="overflow-x-auto">
                        <table className="w-full text-xs border border-slate-800 rounded overflow-hidden min-w-[720px]">
                            <thead className="bg-slate-900/80 text-slate-500">
                                <tr>{['ASSET', 'ROLE', 'CRITICALITY', 'RISK', 'DETECTIONS', 'INCIDENTS', 'SERVICES', 'FIRST SEEN', 'LAST SEEN'].map((h) => (
                                    <th key={h} className="px-3 py-2 text-left font-normal">{h}</th>))}</tr>
                            </thead>
                            <tbody>
                                {data.assets.map((a) => (
                                    <tr key={a.id} className="border-t border-slate-800/60">
                                        <td className="px-3 py-1.5">
                                            <span className="text-emerald-300 break-all">{a.name}</span>
                                            <span className="text-slate-600 ml-1">· {a.entity_type}</span>
                                        </td>
                                        <td className="px-3 py-1.5">
                                            <span className="text-[10px] px-1.5 py-0.5 rounded uppercase"
                                                  style={{ color: TYPE_COLOR[a.asset_type], background: `${TYPE_COLOR[a.asset_type]}1a` }}>
                                                {a.asset_type}
                                            </span>
                                        </td>
                                        <td className="px-3 py-1.5 font-bold" style={{ color: CRIT_COLOR[a.criticality] }}>{a.criticality}</td>
                                        <td className="px-3 py-1.5">{a.risk_score}</td>
                                        <td className="px-3 py-1.5">{a.detections_count}</td>
                                        <td className="px-3 py-1.5">{a.incidents_count}</td>
                                        <td className="px-3 py-1.5 text-slate-400">
                                            {(a.tags || []).join(', ') || '—'}
                                        </td>
                                        <td className="px-3 py-1.5 text-slate-500">{(a.first_seen || '').slice(11, 19)}</td>
                                        <td className="px-3 py-1.5 text-slate-500">{(a.last_seen || '').slice(11, 19)}</td>
                                    </tr>
                                ))}
                                {data.assets.length === 0 && (
                                    <tr><td colSpan={9} className="px-3 py-4 text-center text-slate-600">No assets derived</td></tr>)}
                            </tbody>
                        </table>
                    </div>
                </>
            )}
        </div>
    )
}