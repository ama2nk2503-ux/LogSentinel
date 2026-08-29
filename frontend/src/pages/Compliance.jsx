import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import PageHeader from '../components/PageHeader.jsx'
import Skeleton from '../components/Skeleton.jsx'
import SpotlightCard from '../components/bits/SpotlightCard.jsx'
import { api } from '../lib/api.js'

const STATUS_COLOR = { PASS: '#22c55e', WARN: '#eab308', FAIL: '#ef4444' }

export default function Compliance() {
    const [jobId, setJobId] = useState('')
    const [openReport, setOpenReport] = useState(null)

    const { data } = useQuery({
        queryKey: ['audit', jobId],
        queryFn: () => api(`/audit/${jobId}`),
        enabled: !!jobId,
    })

    const downloadMarkdown = async (framework) => {
        const { report } = await api(`/audit/report/${jobId}/${encodeURIComponent(framework)}`)
        const blob = new Blob([report], { type: 'text/markdown' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `logsentinel-${jobId}-${framework.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.md`
        document.body.appendChild(a)
        a.click()
        a.remove()
        URL.revokeObjectURL(url)
    }

    return (
        <div className="p-4 md:p-6 lg:p-8">
            <PageHeader title="COMPLIANCE AUDIT" />
            <div className="mb-5"><JobPicker value={jobId} onChange={setJobId} /></div>
            {!jobId && <div className="text-sm text-slate-500">Select a processed dataset to audit.</div>}

            {jobId && !data && <Skeleton rows={8} className="mt-4" />}

            {data && (
                <>
                    <div className="grid grid-cols-3 gap-3 mb-6 max-w-[420px]">
                        {[['PASSED', data.summary.passed, '#22c55e'],
                          ['WARNED', data.summary.warned, '#eab308'],
                          ['FAILED', data.summary.failed, '#ef4444']].map(([label, n, color]) => (
                            <SpotlightCard key={label} className="!p-3 text-center">
                                <div className="text-lg font-bold glow-text" style={{ color }}>{n}</div>
                                <div className="text-[10px] tracking-widest text-slate-500">{label}</div>
                            </SpotlightCard>
                        ))}
                    </div>

                    <div className="space-y-4">
                        {data.frameworks.map((fw) => (
                            <div key={fw.name} className="border border-slate-800 rounded bg-slate-900/40">
                                <div className="px-4 py-3 flex items-center justify-between flex-wrap gap-2">
                                    <div>
                                        <div className="text-sm text-slate-100">
                                            <b>{fw.name}</b>
                                            <span style={{ color: STATUS_COLOR[fw.status] }} className="ml-3">
                                                {fw.status}
                                            </span>
                                        </div>
                                        <div className="text-[11px] text-slate-500 mt-0.5">
                                            {fw.passed}/{fw.total} controls passed · score {fw.score}/100
                                        </div>
                                    </div>
                                    <div className="flex gap-2">
                                        <button
                                            onClick={() => setOpenReport(openReport === fw.name ? null : fw.name)}
                                            aria-expanded={openReport === fw.name}
                                            className="text-[11px] text-emerald-400 hover:text-emerald-300"
                                        >
                                            {openReport === fw.name ? 'HIDE FINDINGS' : 'VIEW FINDINGS'}
                                        </button>
                                        <button
                                            onClick={() => downloadMarkdown(fw.name)}
                                            className="text-[11px] text-sky-400 hover:text-sky-300"
                                        >
                                            DOWNLOAD .MD
                                        </button>
                                    </div>
                                </div>
                                {openReport === fw.name && (
                                    <div className="overflow-x-auto border-t border-slate-800">
                                        <table className="w-full text-xs min-w-[560px]">
                                            <thead className="bg-slate-900/80 text-slate-500">
                                                <tr>{['CONTROL', 'TITLE', 'SEV', 'STATUS', 'COUNT', 'EXPECTED', 'NOTE'].map((h) => (
                                                    <th key={h} className="px-3 py-2 text-left font-normal">{h}</th>))}</tr>
                                            </thead>
                                            <tbody>
                                                {fw.findings.map((f) => (
                                                    <tr key={f.control} className="border-t border-slate-800/60">
                                                        <td className="px-3 py-1.5 font-bold text-slate-200">{f.control}</td>
                                                        <td className="px-3 py-1.5 text-slate-300">{f.title}</td>
                                                        <td className="px-3 py-1.5 text-slate-400 uppercase">{f.severity}</td>
                                                        <td className="px-3 py-1.5 font-bold" style={{ color: STATUS_COLOR[f.status] }}>{f.status}</td>
                                                        <td className="px-3 py-1.5">{f.count}</td>
                                                        <td className="px-3 py-1.5 text-slate-500">{f.operator} {f.value}</td>
                                                        <td className="px-3 py-1.5 text-slate-400">{f.note}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
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