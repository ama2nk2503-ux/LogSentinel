import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import { apiDownload } from '../lib/api.js'

const FORMATS = [
    { id: 'json', label: 'JSON', desc: 'Universal schema events + IOCs' },
    { id: 'cef', label: 'CEF', desc: 'ArcSight Common Event Format' },
    { id: 'stix', label: 'STIX 2.1', desc: 'Indicator bundle for TIPs' },
    { id: 'csv', label: 'CSV', desc: 'Spreadsheet-ready rows' },
    { id: 'leef', label: 'LEEF', desc: 'IBM QRadar format' },
    { id: 'syslog', label: 'SYSLOG', desc: 'RFC5424-style relay lines' },
]

export default function ExportPage() {
    const [jobId, setJobId] = useState('')
    const [fmt, setFmt] = useState('json')
    const [error, setError] = useState('')

    const downloadMutation = useMutation({
        mutationFn: () => apiDownload(`/export/${jobId}?format=${fmt}`, `logsentinel.${fmt === 'cef' || fmt === 'leef' ? 'txt' : fmt === 'syslog' ? 'log' : fmt}`),
        onError: (e) => setError(String(e.message)),
        onSuccess: () => setError(''),
    })

    const pdfMutation = useMutation({
        mutationFn: () => apiDownload(`/report/${jobId}`, `logsentinel_report.pdf`),
        onError: (e) => setError(String(e.message)),
        onSuccess: () => setError(''),
    })

    return (
        <div className="p-4 md:p-6 lg:p-8 max-w-3xl">
            <h1 className="text-lg tracking-[0.25em] text-emerald-400 mb-1">SIEM EXPORT</h1>
            <p className="text-xs text-slate-500 mb-6">
                Every payload passes the privacy policy engine and structural validation before download.
            </p>

            <JobPicker value={jobId} onChange={setJobId} />

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 mt-5">
                {FORMATS.map((f) => (
                    <button key={f.id} onClick={() => { setFmt(f.id); setError('') }} disabled={!jobId}
                            className={`p-3 border rounded text-left transition-colors disabled:opacity-40 ${
                                fmt === f.id ? 'border-emerald-500 bg-emerald-500/10' : 'border-slate-800 hover:border-slate-600'}`}>
                        <div className={`text-sm font-bold ${fmt === f.id ? 'text-emerald-400' : 'text-slate-200'}`}>{f.label}</div>
                        <div className="text-[10px] text-slate-500 mt-0.5">{f.desc}</div>
                    </button>
                ))}
            </div>

            <button
                onClick={() => { if (jobId) downloadMutation.mutate() }}
                disabled={!jobId || downloadMutation.isPending}
                className={`mt-6 px-8 py-3 rounded tracking-widest text-sm font-bold ${
                    jobId && !downloadMutation.isPending ? 'bg-emerald-600 hover:bg-emerald-500 text-white' : 'bg-slate-800 text-slate-500 cursor-not-allowed'}`}>
                {downloadMutation.isPending ? 'DOWNLOADING…' : `↓ DOWNLOAD ${fmt.toUpperCase()}`}
            </button>

            {error && <div className="mt-3 text-sm text-red-400">{error}</div>}

            {jobId && (
                <div className="mt-4 text-[11px] text-slate-600">
                  Tip: also available as a branded{' '}
                  <button onClick={() => pdfMutation.mutate()} disabled={pdfMutation.isPending}
                    className="text-sky-400 hover:underline bg-transparent border-none p-0 cursor-pointer text-[11px]">
                    {pdfMutation.isPending ? 'GENERATING…' : 'PDF threat report ↓'}
                  </button>
                </div>
            )}
        </div>
    )
}
