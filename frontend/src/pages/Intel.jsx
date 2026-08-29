import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import PageHeader from '../components/PageHeader.jsx'
import Skeleton from '../components/Skeleton.jsx'
import SpotlightCard from '../components/bits/SpotlightCard.jsx'
import { api } from '../lib/api.js'

const SEV_COLOR = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' }
const VERDICT_COLOR = { malicious: '#ef4444', suspicious: '#f97316', informational: '#3b82f6', unknown: '#64748b' }
const TABS = ['INDICATORS', 'REFERENCE FEED', 'REPUTATION', 'GEO']

function Verdict({ verdict }) {
    return <b style={{ color: VERDICT_COLOR[verdict] || '#64748b' }}>{verdict.toUpperCase()}</b>
}

export default function Intel() {
    const [jobId, setJobId] = useState('')
    const [tab, setTab] = useState('INDICATORS')
    const [open, setOpen] = useState(null)
    const qc = useQueryClient()

    const { data } = useQuery({
        queryKey: ['intel', jobId],
        queryFn: () => api(`/intel/${jobId}`),
        enabled: !!jobId,
    })

    const refQuery = useQuery({
        queryKey: ['intel-reference'],
        queryFn: () => api('/intel/reference'),
        enabled: tab === 'REFERENCE FEED',
    })

    const reloadRef = useMutation({
        mutationFn: () => api('/intel/reference/reload', { method: 'POST' }),
        onSuccess: () => qc.invalidateQueries(['intel-reference']),
    })

    const [repValue, setRepValue] = useState('')
    const repQuery = useQuery({
        queryKey: ['intel-reputation', repValue],
        queryFn: () => api(`/intel/reputation/${encodeURIComponent(repValue)}`),
        enabled: tab === 'REPUTATION' && repValue.trim().length > 0,
    })
    const [geoIp, setGeoIp] = useState('')
    const geoQuery = useQuery({
        queryKey: ['geo-lookup', geoIp],
        queryFn: () => api(`/geo/lookup?ip=${encodeURIComponent(geoIp)}`),
        enabled: tab === 'GEO' && geoIp.trim().length > 0,
    })

    return (
        <div className="p-4 md:p-6 lg:p-8">
            <PageHeader title="THREAT INTELLIGENCE" />
            <div role="tablist" aria-label="Intel views" className="flex flex-wrap gap-1 mb-5 border-b border-slate-800">
                {TABS.map((t) => (
                    <button
                        key={t}
                        role="tab"
                        aria-selected={tab === t}
                        onClick={() => setTab(t)}
                        className={`px-3 py-2 text-[11px] tracking-wider rounded-t transition-colors ${
                            tab === t
                                ? 'text-emerald-400 border-b-2 border-emerald-400 bg-emerald-500/5'
                                : 'text-slate-500 hover:text-slate-300'
                        }`}
                    >
                        {t}{t === 'INDICATORS' && data ? ` (${data.indicators.length})` : ''}
                    </button>
                ))}
            </div>

            {tab === 'INDICATORS' && (
                <>
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
                                                aria-expanded={open === i}
                                                aria-controls={`rep-${i}`}
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
                                            <div id={`rep-${i}`} className="px-4 pb-3 text-[12px] space-y-1.5 border-t border-slate-800 pt-2">
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
                </>
            )}

            {tab === 'REFERENCE FEED' && (
                <div>
                    <div className="flex items-center justify-between max-w-3xl mb-3">
                        <h2 className="text-xs tracking-widest text-slate-500">
                            BUNDLED REFERENCE FEED ({refQuery.data?.count ?? '…'})
                        </h2>
                        <button
                            onClick={() => reloadRef.mutate()}
                            disabled={reloadRef.isPending}
                            className="text-[11px] text-emerald-400 hover:text-emerald-300 disabled:opacity-40"
                        >
                            {reloadRef.isPending ? 'RELOADING…' : 'RELOAD FROM FILE'}
                        </button>
                    </div>
                    {refQuery.isLoading && <Skeleton rows={5} className="mt-2" />}
                    {refQuery.data && (
                        <div className="overflow-x-auto max-w-3xl">
                            <table className="w-full text-xs border border-slate-800 rounded overflow-hidden min-w-[480px]">
                                <thead className="bg-slate-900/80 text-slate-500">
                                    <tr>{['VALUE', 'TYPE', 'THREAT', 'SEV', 'CONF', 'SOURCE', 'TAGS'].map((h) => (
                                        <th key={h} className="px-3 py-2 text-left font-normal">{h}</th>))}</tr>
                                </thead>
                                <tbody>
                                    {refQuery.data.indicators.map((i) => (
                                        <tr key={i.value} className="border-t border-slate-800/60">
                                            <td className="px-3 py-1.5 text-purple-300 break-all">{i.value}</td>
                                            <td className="px-3 py-1.5 text-slate-300">{i.type}</td>
                                            <td className="px-3 py-1.5 text-red-300">{i.threat_type}</td>
                                            <td className="px-3 py-1.5" style={{ color: SEV_COLOR[i.severity] }}>{i.severity}</td>
                                            <td className="px-3 py-1.5">{i.confidence.toFixed(2)}</td>
                                            <td className="px-3 py-1.5 text-slate-500">{i.source}</td>
                                            <td className="px-3 py-1.5 text-slate-400">{i.tags.join(', ')}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}

            {tab === 'REPUTATION' && (
                <div className="max-w-2xl">
                    <div className="flex gap-2 mb-4">
                        <input
                            value={repValue}
                            onChange={(e) => setRepValue(e.target.value)}
                            placeholder="IP / domain / hash"
                            className="flex-1 bg-slate-900 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600"
                            aria-label="Reputation lookup value"
                        />
                    </div>
                    {repValue && !repQuery.data && repQuery.isFetching && <Skeleton rows={4} className="mt-2" />}
                    {repQuery.data && (
                        <SpotlightCard className="!p-4 space-y-3">
                            <div className="flex items-center justify-between">
                                <span className="text-sm break-all text-purple-300">{repQuery.data.value}</span>
                                <Verdict verdict={repQuery.data.verdict} />
                            </div>
                            <div className="grid grid-cols-2 gap-2 text-[12px]">
                                <div className="text-slate-500">TYPE<span className="block text-slate-200">{repQuery.data.type}</span></div>
                                <div className="text-slate-500">THREAT<span className="block text-red-300">{repQuery.data.threat_type || '—'}</span></div>
                                <div className="text-slate-500">SEVERITY<span className="block" style={{ color: SEV_COLOR[repQuery.data.severity] }}>{repQuery.data.severity}</span></div>
                                <div className="text-slate-500">CONFIDENCE<span className="block text-slate-200">{repQuery.data.confidence.toFixed(2)}</span></div>
                            </div>
                            {repQuery.data.sightings.length > 0 && (
                                <div className="text-[12px] text-slate-500">
                                    {repQuery.data.sightings.length} SIGHTING(S) · {repQuery.data.related_events} RELATED EVENTS
                                </div>
                            )}
                        </SpotlightCard>
                    )}
                </div>
            )}

            {tab === 'GEO' && (
                <div className="max-w-2xl">
                    <div className="flex gap-2 mb-4">
                        <input
                            value={geoIp}
                            onChange={(e) => setGeoIp(e.target.value)}
                            placeholder="IP address"
                            className="flex-1 bg-slate-900 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600"
                            aria-label="Geo lookup IP"
                        />
                    </div>
                    {geoIp && !geoQuery.data && geoQuery.isFetching && <Skeleton rows={4} className="mt-2" />}
                    {geoQuery.data && geoQuery.data.kind !== 'unknown' && (
                        <SpotlightCard className="!p-4 space-y-3">
                            <div className="flex items-center justify-between">
                                <span className="text-sm break-all text-emerald-300">{geoQuery.data.ip}</span>
                                <span className="text-[11px] tracking-wider text-slate-500">{geoQuery.data.kind.toUpperCase()}</span>
                            </div>
                            <div className="grid grid-cols-2 gap-2 text-[12px]">
                                <div className="text-slate-500">COUNTRY<span className="block text-slate-200">{geoQuery.data.country}</span></div>
                                <div className="text-slate-500">CITY<span className="block text-slate-200">{geoQuery.data.city || '—'}</span></div>
                                <div className="text-slate-500">ASN / ORG<span className="block text-slate-200">{geoQuery.data.asn} {geoQuery.data.org}</span></div>
                                <div className="text-slate-500">POSITION<span className="block text-slate-400">{geoQuery.data.latitude}, {geoQuery.data.longitude}</span></div>
                            </div>
                        </SpotlightCard>
                    )}
                    {geoQuery.data && geoQuery.data.kind === 'unknown' && (
                        <div className="text-sm text-slate-500">No offline record for <b className="text-slate-300">{geoQuery.data.ip}</b>.</div>
                    )}
                </div>
            )}
        </div>
    )
}