import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import PageHeader from '../components/PageHeader.jsx'
import Skeleton from '../components/Skeleton.jsx'
import { api, classNames } from '../lib/api.js'

const STATUS_TABS = ['ALL', 'OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE']

const SEV_STYLE = {
  LOW: 'text-blue-400 border-blue-800',
  MEDIUM: 'text-yellow-400 border-yellow-700',
  HIGH: 'text-orange-400 border-orange-700',
  CRITICAL: 'text-red-400 border-red-700',
}

const STATUS_STYLE = {
  OPEN: 'text-red-300 border-red-800 bg-red-950/30',
  ACKNOWLEDGED: 'text-amber-300 border-amber-800 bg-amber-950/30',
  RESOLVED: 'text-emerald-300 border-emerald-800 bg-emerald-950/30',
  FALSE_POSITIVE: 'text-slate-400 border-slate-700 bg-slate-900/50',
}

export default function Alerts() {
  const queryClient = useQueryClient()
  const [status, setStatus] = useState('ALL')
  const [severity, setSeverity] = useState('')
  const [notifyMsg, setNotifyMsg] = useState({})
  const [showRules, setShowRules] = useState(false)

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['alerts'] })
    queryClient.invalidateQueries({ queryKey: ['alert-rules'] })
  }

  const { data } = useQuery({
    queryKey: ['alerts', status, severity],
    queryFn: () => {
      const params = new URLSearchParams({ limit: '250' })
      if (status !== 'ALL') params.set('status', status)
      if (severity) params.set('severity', severity)
      return api(`/alerts?${params}`)
    },
    refetchInterval: 5000,
  })

  const ack = useMutation({
    mutationFn: (id) => api(`/alerts/${id}/ack`, { method: 'POST' }),
    onSuccess: () => { invalidate(); setNotifyMsg({}) },
  })
  const resolve = useMutation({
    mutationFn: (id) => api(`/alerts/${id}/resolve`, { method: 'POST' }),
    onSuccess: () => { invalidate(); setNotifyMsg({}) },
  })
  const fp = useMutation({
    mutationFn: (id) => api(`/alerts/${id}/false-positive`, { method: 'POST' }),
    onSuccess: () => { invalidate(); setNotifyMsg({}) },
  })
  const notify = useMutation({
    mutationFn: (id) => api(`/alerts/${id}/notify`, { method: 'POST' }),
    onSuccess: (res, id) => setNotifyMsg((m) => ({ ...m, [id]: res })),
    onError: (err, id) => setNotifyMsg((m) => ({ ...m, [id]: { delivered: false, reason: err.message } })),
  })

  const alerts = data?.alerts || []

  return (
    <div className="p-4 md:p-6 lg:p-8">
      <PageHeader title="ALERTS" subtitle="Deterministic, explainable alerting from correlated incidents, rule matches and high-confidence IOCs." />

      <div className="flex flex-wrap items-center gap-2 mb-4">
        {STATUS_TABS.map((s) => {
          const count = s === 'ALL' ? alerts.length : alerts.filter((a) => a.status === s).length
          return (
            <button key={s} onClick={() => setStatus(s)}
                    aria-pressed={status === s}
                    className={classNames('px-3 py-1.5 rounded border text-xs tracking-wider transition-colors',
                      status === s
                        ? 'border-emerald-700 bg-emerald-950/40 text-emerald-300'
                        : 'border-slate-800 text-slate-400 hover:border-slate-600')}>
              {s} <span>({count})</span>
            </button>
          )
        })}
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}
                aria-label="Severity filter" className="input ml-auto">
          <option value="">all severities</option>
          {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => <option key={s}>{s}</option>)}
        </select>
        <button onClick={() => setShowRules((v) => !v)}
                aria-expanded={showRules}
                className="btn btn-ghost px-3 py-1.5 text-xs">
          {showRules ? 'HIDE' : 'MANAGE'} RULES
        </button>
      </div>

      {showRules && <AlertRules onChanged={invalidate} />}

      {!data && <Skeleton rows={6} className="mt-2" />}

      {data && alerts.length === 0 && (
        <div className="text-sm text-emerald-500 border border-emerald-900 rounded p-4 bg-emerald-950/20">
          No alerts match the current filter. Process a dataset or watch a live stream to generate alerts.
        </div>
      )}

      <div className="space-y-3">
        {alerts.map((a) => (
          <div key={a.id} className="border border-slate-800 rounded-lg overflow-hidden">
            <div className="flex flex-wrap items-center gap-3 px-4 py-2.5 border-b border-slate-800/70 bg-slate-950/40">
              <span className={classNames('px-1.5 py-0.5 border rounded text-[10px] font-bold', SEV_STYLE[a.severity])}>
                {a.severity}
              </span>
              <span className="text-sm font-bold text-slate-100 tracking-wide">{a.title}</span>
              <span className={classNames('ml-auto px-2 py-0.5 border rounded text-[10px] tracking-widest', STATUS_STYLE[a.status])}>
                {a.status}
              </span>
            </div>
            <div className="grid md:grid-cols-2 gap-0">
              <div className="p-4 space-y-1 text-xs">
                <div className="text-slate-400">{a.message}</div>
                <div className="text-slate-500">
                  rule <span className="text-purple-300">{a.alert_rule_id}</span>
                  {' · '}entity <span className="text-sky-300">{a.entity || '—'}</span>
                  {' · '}risk <span className="font-bold text-slate-200">{a.risk_score}</span>/100
                </div>
                {a.created_at && (
                  <div className="text-[10px] text-slate-600">
                    {(a.created_at || '').replace('T', ' ').slice(0, 19)} UTC
                  </div>
                )}
              </div>
              <div className="p-4 flex flex-wrap items-center gap-2 md:justify-end border-t md:border-t-0 md:border-l border-slate-800/60">
                {a.status === 'OPEN' && (
                  <button onClick={() => ack.mutate(a.id)} disabled={actBusy(ack, a.id)}
                          className="btn btn-ghost px-3 py-1.5 text-[11px]">ACK</button>
                )}
                {a.status !== 'RESOLVED' && a.status !== 'FALSE_POSITIVE' && (
                  <>
                    <button onClick={() => resolve.mutate(a.id)} disabled={actBusy(resolve, a.id)}
                            className="btn btn-ghost px-3 py-1.5 text-[11px]">RESOLVE</button>
                    <button onClick={() => fp.mutate(a.id)} disabled={actBusy(fp, a.id)}
                            className="btn btn-danger px-3 py-1.5 text-[11px]">FALSE POSITIVE</button>
                  </>
                )}
                <button onClick={() => notify.mutate(a.id)} disabled={notify.isPending}
                        className="btn btn-ghost px-3 py-1.5 text-[11px]" title="Deliver to configured channels">
                  NOTIFY
                </button>
              </div>
            </div>
            {notifyMsg[a.id] && (
              <div className={classNames('px-4 py-2 text-[11px]',
                notifyMsg[a.id].delivered ? 'text-emerald-300' : 'text-amber-300')}>
                {notifyMsg[a.id].delivered
                  ? `Alert delivered via ${notifyMsg[a.id].channels.join(', ').toUpperCase()}`
                  : notifyMsg[a.id].reason}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function actBusy(mut, id) {
  return mut.isPending && mut.variables === id
}

function AlertRules({ onChanged }) {
  const { data } = useQuery({
    queryKey: ['alert-rules'],
    queryFn: () => api('/alert-rules').then((d) => d.rules),
  })
  const queryClient = useQueryClient()

  const toggle = useMutation({
    mutationFn: ({ id, enabled }) =>
      api(`/alert-rules/${id}`, { method: 'PUT', body: JSON.stringify({ enabled }) }),
    onSuccess: onChanged,
  })

  const reload = useMutation({
    mutationFn: () => api('/alert-rules/reload', { method: 'POST' }),
    onSuccess: onChanged,
  })

  return (
    <div className="border border-slate-800 rounded-lg mb-4">
      <div className="px-4 py-2 flex items-center justify-between border-b border-slate-800/70">
        <span className="text-[10px] tracking-widest text-slate-500">ALERT RULES — DETERMINISTIC + EXPLAINABLE</span>
        <div className="flex gap-2">
          <button onClick={() => reload.mutate()} disabled={reload.isPending}
                  className="btn btn-ghost px-3 py-1 text-[10px]"
                  title="Reset rules from rules/alert_rules.yaml">RELOAD FROM FILE</button>
        </div>
      </div>
      {!data && <div className="p-3 text-xs text-slate-500">Loading rules…</div>}
      {data && (
        <table className="w-full text-xs" aria-label="Alert rules">
          <thead>
            <tr>{['RULE ID', 'SOURCE', 'GATE', 'SEV', 'ON', 'ACTION'].map((h) => (
              <th key={h} className="table-header">{h}</th>))}</tr>
          </thead>
          <tbody>
            {data.map((r) => (
              <tr key={r.rule_id} className="border-t border-slate-800/60">
                <td className="table-cell text-purple-300 font-mono">{r.rule_id}
                  <div className="text-slate-500 text-[10px]">{r.name}</div>
                </td>
                <td className="table-cell text-slate-300">{r.source_type}</td>
                <td className="table-cell text-slate-400">
                  {r.source_type === 'incident' ? `risk ≥ ${r.min_risk}`
                    : r.source_type === 'ioc' ? `confidence ≥ ${r.min_confidence}`
                    : r.match_rule_id || r.match_category || `${r.source_type} ×${r.threshold}`}
                </td>
                <td className="table-cell">{r.severity}</td>
                <td className={classNames('table-cell', r.enabled ? 'text-emerald-400' : 'text-slate-600')}>
                  {r.enabled ? 'ON' : 'OFF'}
                </td>
                <td className="table-cell">
                  <button onClick={() => toggle.mutate({ id: r.rule_id, enabled: !r.enabled })}
                          disabled={toggle.isPending}
                          className="btn btn-ghost px-2 py-0.5 text-[10px]">
                    {r.enabled ? 'DISABLE' : 'ENABLE'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <CreateRuleForm onCreated={() => { onChanged(); queryClient.invalidateQueries({ queryKey: ['alert-rules'] }) }} />
    </div>
  )
}

function CreateRuleForm({ onCreated }) {
  const [name, setName] = useState('')
  const [sourceType, setSourceType] = useState('detection')
  const [severity, setSeverity] = useState('MEDIUM')
  const [threshold, setThreshold] = useState(1)

  const create = useMutation({
    mutationFn: () => api('/alert-rules', {
      method: 'POST',
      body: JSON.stringify({ name, source_type: sourceType, severity, threshold }),
    }),
    onSuccess: () => { setName(''); onCreated() },
  })

  return (
    <form onSubmit={(e) => { e.preventDefault(); if (name.trim()) create.mutate() }}
          className="flex flex-wrap gap-2 items-center px-4 py-3 border-t border-slate-800/70">
      <span className="text-[10px] tracking-widest text-slate-500">NEW RULE</span>
      <input value={name} onChange={(e) => setName(e.target.value)} placeholder="rule name"
             aria-label="Rule name" className="input flex-1 min-w-40" />
      <select value={sourceType} onChange={(e) => setSourceType(e.target.value)}
              aria-label="Rule source type" className="input">
        {['detection', 'incident', 'ioc'].map((s) => <option key={s}>{s}</option>)}
      </select>
      <select value={severity} onChange={(e) => setSeverity(e.target.value)}
              aria-label="Rule severity" className="input">
        {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => <option key={s}>{s}</option>)}
      </select>
      <input type="number" min="1" value={threshold} onChange={(e) => setThreshold(Number(e.target.value))}
             aria-label="Rule threshold" className="input w-20" />
      <button type="submit" disabled={!name.trim() || create.isPending}
              className="btn btn-primary px-3 py-1.5 text-[11px]">CREATE</button>
      {create.isError && <span className="text-xs text-red-400">Failed to create rule</span>}
    </form>
  )
}