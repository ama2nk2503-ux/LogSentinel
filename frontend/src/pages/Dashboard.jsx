import { useEffect, useState } from 'react'
import { memo } from 'react'
import { useParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { api, apiDownload } from '../lib/api.js'
import PageHeader from '../components/PageHeader.jsx'

const SEV_COLORS = { LOW: '#3b82f6', MEDIUM: '#eab308', HIGH: '#f97316', CRITICAL: '#ef4444', UNKNOWN: '#475569' }
const PIE_COLORS = ['#10b981', '#3b82f6', '#a855f7', '#f97316', '#ef4444', '#14b8a6', '#eab308']

const Card = memo(function Card({ label, value, tone = 'slate' }) {
  const tones = {
    slate: 'text-slate-100',
    green: 'text-emerald-400',
    orange: 'text-orange-400',
    red: 'text-red-400',
    blue: 'text-blue-400',
    purple: 'text-purple-400',
  }
  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded p-4">
      <div className="text-[10px] tracking-widest text-slate-500 mb-2">{label}</div>
      <div className={`text-2xl font-bold ${tones[tone]}`}>{value ?? 0}</div>
    </div>
  )
})

const ChartBox = memo(function ChartBox({ title, children }) {
  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded p-4">
      <div className="text-[10px] tracking-widest text-slate-500 mb-3">{title}</div>
      <div className="h-48 md:h-56" role="img" aria-label={title}>{children}</div>
    </div>
  )
})

export default function Dashboard() {
  const { jobId: routeJobId } = useParams()
  const [jobId, setJobId] = useState(routeJobId || '')
  const [exportError, setExportError] = useState('')

  useEffect(() => {
    if (routeJobId) setJobId(routeJobId)
  }, [routeJobId])

  const { data, error } = useQuery({
    queryKey: ['dashboard', jobId],
    queryFn: () => api(`/dashboard/${jobId}`),
    enabled: !!jobId,
    refetchInterval: 2000,
  })

  const exportMutation = useMutation({
    mutationFn: async () => {
      await apiDownload(`/export/${jobId}?format=json`, 'logsentinel.json')
      setExportError('')
    },
    onError: (e) => setExportError(String(e.message || e)),
  })

  if (!jobId) {
    return (
      <div className="p-4 md:p-6 lg:p-8">
        <PageHeader title="SOC DASHBOARD" />
        <div className="text-sm text-slate-500 mb-3">Select a processed dataset:</div>
        <JobPicker value={jobId} onChange={setJobId} />
      </div>
    )
  }

  if (error) return <div className="p-8 text-red-400">{error.message}</div>
  if (!data) return <div className="p-8 text-slate-400">Loading telemetry…</div>

  const { job, cards, charts } = data
  const sevData = charts.severity.map((s) => ({ name: s.label, value: s.count }))

  return (
    <div className="p-4 md:p-6 lg:p-8">
      <div className="flex items-baseline justify-between mb-1">
        <h1 className="text-lg tracking-[0.25em] text-emerald-400">SOC DASHBOARD</h1>
        <span className="text-xs text-slate-500">{job.filename}</span>
      </div>
      <div className="text-[11px] text-slate-500 mb-5 flex gap-4 items-center">
        <span>FORMAT: <b className="text-slate-300">{job.detected_format || '—'}</b></span>
        {job.format_confidence != null && (
          <span>CONFIDENCE: <b className="text-emerald-400">{job.format_confidence}%</b></span>
        )}
        <span>STAGE: <b className="text-slate-300">{job.stage}</b></span>
        <button
          onClick={() => exportMutation.mutate()}
          disabled={exportMutation.isPending}
          className="ml-auto px-3 py-1 text-[11px] tracking-wider border border-emerald-700 text-emerald-400 hover:bg-emerald-500/10 rounded disabled:opacity-40"
        >
          {exportMutation.isPending ? 'EXPORTING…' : 'EXPORT JSON ↓'}
        </button>
      </div>
      {exportError && <div className="mb-4 text-xs text-red-400">{exportError}</div>}

      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 xl:grid-cols-7 gap-3 mb-6">
        <Card label="TOTAL EVENTS" value={cards.total_events} />
        <Card label="NORMALIZED" value={cards.normalized} tone="blue" />
        <Card label="THREATS" value={cards.threats} tone="orange" />
        <Card label="CRITICAL" value={cards.critical} tone="red" />
<Card label="IOCs" value={cards.iocs_unique} tone="purple" />
<Card label="PII EVENTS" value={cards.pii_events} />
<Card label="REDACTED" value={cards.redacted} tone="green" />
{cards.ml_model > 0 && <Card label="ML ANOMALIES" value={cards.ml_anomalies} tone="red" />}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <ChartBox title="THREAT SEVERITY DISTRIBUTION">
          {sevData.length === 0 ? <Empty /> : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={75}>
                  {sevData.map((s) => <Cell key={s.name} fill={SEV_COLORS[s.name] || '#475569'} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151' }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </ChartBox>

        <ChartBox title="EVENTS OVER TIME">
          {charts.timeline.length === 0 ? <Empty /> : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={charts.timeline}>
                <defs>
                  <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#10b981" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#10b981" stopOpacity={0.05} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#374151" strokeDasharray="3 3" />
                <XAxis dataKey="minute" tick={{ fill: '#94a3b8', fontSize: 9 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 9 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151' }} />
                <Area type="monotone" dataKey="count" stroke="#10b981" fill="url(#g1)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </ChartBox>

        <ChartBox title="TOP SOURCE IPs">
          {charts.top_ips.length === 0 ? <Empty /> : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart layout="vertical" data={charts.top_ips.map((t) => ({ ip: t.label, n: t.count }))}>
                <CartesianGrid stroke="#374151" strokeDasharray="3 3" />
                <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 9 }} allowDecimals={false} />
                <YAxis type="category" dataKey="ip" width={110} tick={{ fill: '#94a3b8', fontSize: 9 }} />
                <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151' }} />
                <Bar dataKey="n" fill="#3b82f6" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartBox>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <ChartBox title="EVENT TYPES">
          {charts.event_types.length === 0 ? <Empty /> : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={charts.event_types.map((t) => ({ name: t.label, value: t.count }))}
                     dataKey="value" nameKey="name" outerRadius={70}>
                  {charts.event_types.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151' }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </ChartBox>

        <ChartBox title="IOC TYPES EXTRACTED">
          {charts.ioc_types.length === 0 ? <Empty msg="No IOCs extracted" /> : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={charts.ioc_types.map((t) => ({ type: t.label.toUpperCase(), n: t.count }))}>
                <CartesianGrid stroke="#374151" strokeDasharray="3 3" />
                <XAxis dataKey="type" tick={{ fill: '#94a3b8', fontSize: 9 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 9 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151' }} />
                <Bar dataKey="n" fill="#a855f7" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartBox>

        <ChartBox title="DETECTED THREAT TYPES">
          {charts.threat_types.length === 0 ? <Empty msg="No threats detected" /> : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={charts.threat_types.map((t) => ({ t: t.label, n: t.count }))} layout="vertical">
                <CartesianGrid stroke="#374151" strokeDasharray="3 3" />
                <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 9 }} allowDecimals={false} />
                <YAxis type="category" dataKey="t" width={110} tick={{ fill: '#fca5a5', fontSize: 9 }} />
                <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151' }} />
                <Bar dataKey="n" fill="#ef4444" radius={[0, 3, 3, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartBox>
      </div>
    </div>
  )
}

function Empty({ msg = 'No data' }) {
  return <div className="h-full flex items-center justify-center text-xs text-slate-600">{msg}</div>
}