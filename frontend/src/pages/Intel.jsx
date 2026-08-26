import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import Skeleton from '../components/Skeleton.jsx'
import { api } from '../lib/api.js'

const SEV_COLOR = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' }

export default function Intel() {
    const [jobId, setJobId] = useState('')
    const [open, setOpen] = useState(null)

    const { data } = useQuery({
        queryKey: ['intel', jobId],
        queryFn: () => api(`/intel/${jobId}`),
        enabled: !!jobId,
    })

    return (
        <div className="p-4 md:p-6 lg:p-8">
            <h1 className="text-lg tracking-[0.25em] text-emerald-400 mb-5">THREAT INTELLIGENCE</h1>
            <div className="mb-5"><JobPicker value={jobId} onChange={setJobId} /></div>
            {!jobId && <div className="text-sm text-slate-500">Select a processed dataset.</div>}

            {jobId && !data && <Skeleton rows={6} className="mt-4" />}

            {data && (
                <>
                    <h2 className="text-xs tracking-widest text-slate-500 mb-2">
                        INDICATORS ({data.indicators.length})
                    </h2>
                    <div className="overflow-x-auto">
                    <table className="w-full text-xs border border-slate-800 rounded overflow-hidden mb-8 min-w-[500px]">
                        <thead className="bg-slate-900/80 text-slate-500">
                            <tr>{['INDICATOR', 'TYPE', 'THREAT', 'SEV', 'CONF', 'EVENTS', 'FIRST SEEN', 'LAST SEEN'].map((h) => (
                                <th key={h} className="px-3 py-2 text-left font-normal">{h}</th>))}</tr>
                        </thead>
                        <tbody>
                            {data.indicators.map((i) => (
                                <tr key={i.value + i.type} className="border-t border-slate-800/60">
                                    <td className="px-3 py-1.5 text-purple-300 break-all max-w-[220px]">{i.value}</td>
                                    <td className="px-3 py-1.5 text-slate-300">{i.type}</td>
                                    <td className="px-3 py-1.5 text-red-300">{i.threat_type}</td>
                                    <td className="px-3 py-1.5" style={{ color: SEV_COLOR[i.severity] }}>{i.severity}</td>
                                    <td className="px-3 py-1.5">{i.confidence.toFixed(2)}</td>
                                    <td className="px-3 py-1.5 font-bold">{i.related_events}</td>
                                    <td className="px-3 py-1.5 text-slate-500">{(i.first_seen || '').slice(11, 19)}</td>
                                    <td className="px-3 py-1.5 text-slate-500">{(i.last_seen || '').slice(11, 19)}</td>
                                </tr>
                            ))}
                            {data.indicators.length === 0 && (
                                <tr><td colSpan={8} className="px-3 py-4 text-center text-slate-600">No indicators</td></tr>)}
                        </tbody>
                    </table>
                    </div>

                    <h2 className="text-xs tracking-widest text-slate-500 mb-2">
                        THREAT REPORTS ({data.reports.length})
                    </h2>
                    <div className="space-y-2 max-w-3xl">
                        {data.reports.map((r, i) => (
                            <div key={r.title + i} className="border border-slate-800 rounded bg-slate-900/40">
                                <button onClick={() => setOpen(open === i ? null : i)}
                                        className="w-full px-4 py-2.5 flex justify-between items-center hover:bg-slate-800/30 rounded">
                                    <span className="text-sm text-slate-200">
                                        <b className="text-red-300">{r.title}</b>
                                        <span className="text-slate-500 ml-2 text-[11px]">
                                            src {r.source} · {r.events} events · conf {r.confidence}
                                        </span>
                                    </span>
                                    <span className="flex gap-2 items-center text-[11px]">
                                        <span style={{ color: SEV_COLOR[r.severity] }}>{r.severity}</span>
                                        <b className={r.classification === 'MALICIOUS' ? 'text-red-400' : 'text-orange-300'}>
                                            {r.risk_score}
                                        </b>
                                    </span>
                                </button>
                                {open === i && (
                                    <div className="px-4 pb-3 text-[12px] space-y-1.5 border-t border-slate-800 pt-2">
                                        {r.why.map((w) => (
                                            <div key={w} className="text-emerald-400">✓ <span className="text-slate-300">{w}</span></div>
                                        ))}
                                        <div className="pt-1 text-sky-300">➜ {r.recommended_response}</div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </>
            )}
        </div>
    )
}
