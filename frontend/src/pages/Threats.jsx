import { useEffect, useId, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import PageHeader from '../components/PageHeader.jsx'
import Skeleton from '../components/Skeleton.jsx'
import { api, classNames } from '../lib/api.js'
import { useRole, hasRole } from '../lib/AuthContext.jsx'

const CLASS_STYLE = {
  MALICIOUS: 'border-red-700 bg-red-950/30 text-red-300',
  SUSPICIOUS: 'border-orange-700 bg-orange-950/20 text-orange-300',
  BENIGN: 'border-slate-700 bg-slate-900/40 text-slate-400',
}

const STATUS_STYLE = {
  NEW: 'text-red-300 border-red-800',
  ACKNOWLEDGED: 'text-amber-300 border-amber-800',
  IN_PROGRESS: 'text-sky-300 border-sky-800',
  ESCALATED: 'text-fuchsia-300 border-fuchsia-800',
  RESOLVED: 'text-emerald-300 border-emerald-800',
  FALSE_POSITIVE: 'text-slate-400 border-slate-700',
}

const STATUSES = ['NEW', 'ACKNOWLEDGED', 'IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE']

export default function Threats() {
  const [jobId, setJobId] = useState('')
  const [tab, setTab] = useState('incidents')
  const queryClient = useQueryClient()

  const { data } = useQuery({
    queryKey: ['threats', jobId],
    queryFn: () => api(`/threats/${jobId}`),
    enabled: !!jobId,
  })

  // Workstream A/E: OPSEC actor attribution + job knowledge graph (on demand)
  const opsec = useQuery({
    queryKey: ['opsec', jobId],
    queryFn: () => api(`/opsec/${jobId}`),
    enabled: !!jobId && tab === 'opsec',
  })

  const knowledge = useQuery({
    queryKey: ['knowledge', jobId],
    queryFn: () => api(`/knowledge/${jobId}`),
    enabled: !!jobId && tab === 'opsec',
  })

  const setStatus = useMutation({
    mutationFn: ({ id, status }) =>
      api(`/threats/${id}/status`, { method: 'POST', body: JSON.stringify({ status }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['threats', jobId] }),
  })

  const addNote = useMutation({
    mutationFn: ({ id, note }) =>
      api(`/threats/${id}/note`, { method: 'POST', body: JSON.stringify({ note }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['threats', jobId] }),
  })

  const assign = useMutation({
    mutationFn: ({ id, assignee }) =>
      api(`/threats/${id}/assign`, { method: 'POST', body: JSON.stringify({ assignee }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['threats', jobId] }),
  })

  // M5 item 3: recommended & simulated response actions (SOAR-lite).
  const simulate = useMutation({
    mutationFn: ({ id, actionId }) =>
      api(`/incidents/${id}/actions/${actionId}/simulate`, { method: 'POST' }),
    onSuccess: (_res, vars) =>
      queryClient.invalidateQueries({ queryKey: ['threat-actions', vars.id] }),
  })
  const canAct = hasRole('analyst', useRole())

  // M4 item 7: rule-vs-ML agreement panel (pure UI — data both halves already produce)
  const ml = useQuery({
    queryKey: ['ml', jobId],
    queryFn: () => api(`/ml/${jobId}`),
    enabled: !!jobId,
  })

  return (
    <div className="p-4 md:p-6 lg:p-8">
      <PageHeader title="THREAT CORRELATION" />
      <div className="mb-5 flex flex-wrap items-center gap-3">
        <JobPicker value={jobId} onChange={setJobId} />
        <div className="flex gap-1 border border-slate-800 rounded-lg overflow-hidden" role="tablist" aria-label="Correlation views">
          <button role="tab" aria-selected={tab === 'incidents'} onClick={() => setTab('incidents')}
                  className={classNames('px-3 py-1.5 text-[11px] tracking-widest transition-colors',
                    tab === 'incidents' ? 'bg-emerald-900/40 text-emerald-300' : 'text-slate-500 hover:text-slate-300')}>
            INCIDENTS
          </button>
          <button role="tab" aria-selected={tab === 'opsec'} onClick={() => setTab('opsec')}
                  className={classNames('px-3 py-1.5 text-[11px] tracking-widest transition-colors',
                    tab === 'opsec' ? 'bg-emerald-900/40 text-emerald-300' : 'text-slate-500 hover:text-slate-300')}>
            OPSEC ATTRIBUTION
          </button>
        </div>
      </div>

      {!jobId && <div className="text-sm text-slate-500">Select a processed dataset.</div>}

      {tab === 'opsec' && jobId && (
        <OpsecView jobId={jobId} opsec={opsec.data} knowledge={knowledge.data} loading={opsec.isLoading} />
      )}

      {tab === 'incidents' && (
      <>
      {jobId && !data && <Skeleton rows={5} className="mt-4" />}

      {data && data.incidents.length === 0 && (
        <div className="text-sm text-emerald-500 border border-emerald-900 rounded p-4 bg-emerald-950/20">
          ✓ No threat incidents correlated for this dataset.
        </div>
      )}

      {data && data.incidents.length > 0 && ml.data && (
        <RuleVsMlPanel incidents={data.incidents} ml={ml.data} />
      )}

      <div className="space-y-4">
        {data?.incidents.map((inc) => (
          <div key={inc.id || inc.entity + inc.title} className={classNames('border rounded-lg overflow-hidden', CLASS_STYLE[inc.classification])}>
            <div className="px-5 py-3 flex items-center justify-between">
              <div>
                <div className="font-bold tracking-wide">{inc.title}</div>
                <div className="text-[11px] opacity-70 mt-0.5">
                  entity <b>{inc.entity}</b> · {inc.category} · {inc.classification}
                </div>
              </div>
              <div className="flex items-center gap-3">
                <StatusChip inc={inc} />
                <RiskRing score={inc.risk_score} severity={inc.severity} />
              </div>
            </div>

            {inc.killchain && inc.killchain.tactics_order && (
              <KillChain killchain={inc.killchain} />
            )}

            <IncidentTriage inc={inc} mutations={{ setStatus, addNote, assign }} />

            <div className="grid md:grid-cols-2 gap-0 border-t border-inherit">
              <div className="p-4 border-r border-slate-800/50">
                <div className="text-[10px] tracking-widest text-slate-500 mb-2">WHY WAS THIS DETECTED?</div>
                {inc.ai_summary && (
                  <div className="mb-3 border-l-2 border-purple-700 pl-2" data-testid="ai-summary">
                    <div className="text-[11px] text-purple-300">{inc.ai_summary.narration}</div>
                    <div className="text-[10px] text-slate-500 mt-1">⚠ {inc.ai_summary.disclaimer}</div>
                  </div>
                )}
                {inc.description && (
                  <div className="mb-3 border-l-2 border-emerald-700 pl-2" data-testid="what-was-found">
                    <div className="text-[10px] uppercase tracking-widest text-emerald-400 mb-1">What was found</div>
                    <div className="text-[11px] text-slate-200 leading-relaxed">{stripTags(inc.description.summary)}</div>
                    <div className="text-[10px] text-slate-500 mt-1">{inc.description.provenance}</div>
                  </div>
                )}
                <ul className="space-y-1">
                  {inc.reasons.map((r) => (
                    <li key={r} className="text-xs flex gap-2"><span className="text-emerald-500">✓</span><span className="text-slate-300">{r}</span></li>
                  ))}
                </ul>
                {inc.recommended_response && (
                  <div className="mt-3 text-[11px] text-sky-300 border-l-2 border-sky-700 pl-2">{inc.recommended_response}</div>
                )}
              </div>
              <div className="p-4">
                <div className="text-[10px] tracking-widest text-slate-500 mb-2">ATTACK TIMELINE ({inc.timeline.length})</div>
                <div className="max-h-44 overflow-auto pr-1">
                  <ol className="relative border-l border-slate-700 ml-2 space-y-2">
                    {inc.timeline.map((t, i) => (
                      <li key={i} className="ml-3">
                        <span className="absolute -left-[5px] w-2 h-2 rounded-full mt-1"
                              style={{ background: t.severity === 'CRITICAL' ? '#ef4444' : t.severity === 'HIGH' ? '#f97316' : '#eab308' }} />
                        <div className="text-[10px] text-slate-500">{(t.ts || '—').replace('T', ' ').slice(0, 19)} · {t.rule_name}</div>
                        <div className="text-[11px] text-slate-300 truncate">{t.excerpt}</div>
                      </li>
                    ))}
                  </ol>
                </div>
              </div>
            </div>

            <RecommendedResponse inc={inc} simulate={simulate} canAct={canAct} />
          </div>
        ))}
      </div>

      {data && data.detections.length > 0 && (
        <div className="mt-8">
          <h2 className="text-xs tracking-widest text-slate-500 mb-2">ALL RULE MATCHES</h2>
          <table className="w-full text-xs border border-slate-800 rounded overflow-hidden">
            <thead className="bg-slate-900/80 text-slate-500">
              <tr>{['RULE', 'NAME', 'CATEGORY', 'ENTITY', 'SEV', 'RISK'].map((h) => (
                <th key={h} className="px-3 py-2 text-left font-normal">{h}</th>))}</tr>
            </thead>
            <tbody>
              {data.detections.map((d) => (
                <tr key={d.id} className="border-t border-slate-800/60">
                  <td className="px-3 py-1.5 text-purple-300">{d.rule_id}</td>
                  <td className="px-3 py-1.5 text-slate-300">{d.rule_name}</td>
                  <td className="px-3 py-1.5 text-slate-400">{d.category}</td>
                  <td className="px-3 py-1.5 text-sky-300">{d.entity}</td>
                  <td className="px-3 py-1.5">{d.severity}</td>
                  <td className="px-3 py-1.5 font-bold">{d.risk_score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      </>
      )}
    </div>
  )
}

function StatusChip({ inc }) {
  return (
    <span className={classNames('px-2 py-0.5 border rounded text-[10px] tracking-widest',
      STATUS_STYLE[inc.status] || STATUS_STYLE.NEW)}>
      {inc.status || 'NEW'} {inc.false_positive ? ' · FP' : ''}
    </span>
  )
}

function slaAgeMinutes(createdAt) {
  if (!createdAt) return null
  const base = createdAt.replace(' ', 'T').includes('T') ? createdAt : createdAt.replace(' ', 'T') + 'Z'
  const ms = Date.parse(base)
  if (Number.isNaN(ms)) return null
  return Math.max(0, Math.round((Date.now() - ms) / 60000))
}

function IncidentTriage({ inc, mutations }) {
  const [note, setNote] = useState('')
  const [assignee, setAssignee] = useState('')
  const [timelineOpen, setTimelineOpen] = useState(false)
  const age = slaAgeMinutes(inc.created_at)
  const gating = ['NEW', 'ACKNOWLEDGED', 'IN_PROGRESS', 'ESCALATED'].includes(inc.status)

  return (
    <div className="px-5 py-3 border-t border-inherit bg-black/10">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] tracking-widest text-slate-500">TRIAGE</span>
        <select
          value={inc.status || 'NEW'}
          onChange={(e) => mutations.setStatus.mutate({ id: inc.id, status: e.target.value })}
          aria-label={`Set status for ${inc.title}`}
          className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-[11px] text-slate-300 focus:outline-none focus:border-emerald-600">
          {STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        {gating && age !== null && (
          <span className={classNames('px-2 py-0.5 rounded text-[10px] border',
            age > 60 ? 'text-red-400 border-red-800 bg-red-950/30' : 'text-amber-300 border-amber-800 bg-amber-950/20')}
                title="Time since first correlation (SLA)">
            SLA {age}m
          </span>
        )}
        <span className="text-[11px] text-slate-400">
          {inc.assignee ? `assigned: ${inc.assignee}` : 'unassigned'}
        </span>
        <button onClick={() => setTimelineOpen(true)}
                className="btn btn-ghost px-3 py-1 text-[11px] ml-auto">
          VIEW TIMELINE
        </button>
      </div>
      <div className="flex flex-wrap gap-2 mt-2">
        <input value={assignee} onChange={(e) => { setAssignee(e.target.value); mutations.assign.mutate({ id: inc.id, assignee: e.target.value }) }}
               placeholder="assign analyst…" aria-label={`Assignee for ${inc.title}`}
               className="input w-40" />
        <form className="flex-1 flex gap-2 min-w-52" onSubmit={(e) => {
          e.preventDefault()
          if (note.trim()) { mutations.addNote.mutate({ id: inc.id, note }); setNote('') }
        }}>
          <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="triage note…"
                 aria-label={`Add note to ${inc.title}`} className="input flex-1" />
          <button type="submit" className="btn btn-ghost px-3 py-1 text-[11px]">ADD NOTE</button>
        </form>
      </div>
      {inc.notes?.length > 0 && (
        <ul className="mt-2 space-y-1">
          {inc.notes.map((n, i) => (
            <li key={i} className="text-[11px] text-slate-400 border-l-2 border-slate-700 pl-2">
              <span className="text-slate-600">{(n.at || '').replace('T', ' ').slice(0, 19)}</span>{' '}
              <span className="text-slate-300">{n.note}</span>
            </li>
          ))}
        </ul>
      )}
      {timelineOpen && <TimelineModal incidentId={inc.id} title={inc.title} onClose={() => setTimelineOpen(false)} />}
    </div>
  )
}

function TimelineModal({ incidentId, title, onClose }) {
  const panelRef = useRef(null)
  const titleId = useId()

  const { data, isFetching } = useQuery({
    queryKey: ['timeline', incidentId],
    queryFn: () => api(`/incidents/${incidentId}/timeline`),
    enabled: true,
  })

  useEffect(() => {
    panelRef.current?.focus()
  }, [])

  return (
    <div
      ref={panelRef}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onKeyDown={(e) => { if (e.key === 'Escape') onClose() }}
      className="mt-3 border border-emerald-900/60 rounded-lg overflow-hidden outline-none"
    >
      <div className="bg-emerald-900/20 px-4 py-2 flex justify-between items-center">
        <span id={titleId} className="text-xs tracking-widest text-emerald-400">
          INVESTIGATION TIMELINE — {title}
        </span>
        <button onClick={onClose} aria-label="Close investigation timeline" className="text-xs text-slate-400 hover:text-white">✕ close</button>
      </div>
      <div className="p-4 bg-slate-950/60 max-h-[55vh] overflow-auto">
        {isFetching && !data && <Skeleton rows={4} />}
        {data && <TimelineBars timeline={data} />}
      </div>
    </div>
  )
}

function TimelineBars({ timeline }) {
  const [open, setOpen] = useState(null)
  const phases = timeline.phases || []
  if (phases.length === 0) {
    return <div className="text-xs text-slate-500">No phase-mapped evidence for this incident.</div>
  }
  const stamps = phases.flatMap((p) => [p.start, p.end]).filter(Boolean)
  let min = null
  let max = null
  for (const s of stamps) {
    const t = Date.parse(s)
    if (!Number.isNaN(t)) {
      min = min === null ? t : Math.min(min, t)
      max = max === null ? t : Math.max(max, t)
    }
  }
  const span = max && min ? Math.max(1, max - min) : 1
  const toPct = (s) => {
    if (!s) return null
    const t = Date.parse(s)
    if (Number.isNaN(t) || min === null) return null
    return ((t - min) / span) * 100
  }

  return (
    <div className="space-y-2">
      <div className="text-[10px] tracking-widest text-slate-500">
        {timeline.title} · {timeline.phases.length} PHASE(S) · risk {timeline.risk_score}/100
      </div>
      {phases.map((p) => {
        const left = toPct(p.start)
        const right = toPct(p.end)
        const width = left !== null && right !== null ? Math.max(2, right - left) : null
        const isOpen = open === p.tactic
        return (
          <div key={p.tactic} className="text-[11px]">
            <button onClick={() => setOpen(isOpen ? null : p.tactic)}
                    aria-expanded={isOpen}
                    className="flex w-full items-center gap-3 px-1 py-1 rounded hover:bg-slate-800/30 text-left">
              <span className="w-32 shrink-0 text-slate-400 uppercase tracking-wider text-[10px]">
                {p.tactic}
              </span>
              <span className="relative flex-1 h-4 bg-slate-900 border border-slate-800 rounded overflow-hidden">
                {left !== null && width !== null && (
                  <span className="absolute inset-y-0 bg-gradient-to-r from-red-500/70 to-orange-500/70"
                        style={{ left: `${left}%`, width: `${width}%` }} />
                )}
              </span>
              <span className="w-12 shrink-0 text-right text-slate-500">{p.count}</span>
            </button>
            {isOpen && (
              <ul className="ml-40 pb-1 space-y-1">
                {p.entries.map((e, i) => (
                  <li key={i} className="border-l-2 border-slate-700 pl-2">
                    <div className="text-[10px] text-slate-500">{(e.ts || '—').replace('T', ' ').slice(0, 19)} · {e.rule_name}</div>
                    <div className="text-slate-300 truncate">{e.excerpt}</div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )
      })}
      {timeline.unmapped_rule_ids?.length > 0 && (
        <div className="text-[10px] text-slate-600">
          unmapped rules: {timeline.unmapped_rule_ids.join(', ')}
        </div>
      )}
    </div>
  )
}

function RiskRing({ score, severity }) {
  const color = severity === 'CRITICAL' ? '#ef4444' : severity === 'HIGH' ? '#f97316' : severity === 'MEDIUM' ? '#eab308' : '#3b82f6'
  return (
    <div className="w-14 h-14 rounded-full grid place-items-center shrink-0"
         style={{ background: `conic-gradient(${color} ${score * 3.6}deg, #374151 0deg)` }}>
      <div className="w-11 h-11 rounded-full bg-bg-base grid place-items-center">
        <span className="text-sm font-bold" style={{ color }}>{score}</span>
      </div>
    </div>
  )
}

const TACTIC_SHORT = {
  reconnaissance: 'RECON', 'resource-development': 'RESDEV', 'initial-access': 'INIT',
  execution: 'EXEC', persistence: 'PERSIST', 'privilege-escalation': 'PRIVESC',
  'defense-evasion': 'DEF-EV', 'credential-access': 'CREDS', discovery: 'DISC',
  'lateral-movement': 'LATERAL', collection: 'COLLECT', 'command-and-control': 'C2',
  exfiltration: 'EXFIL', impact: 'IMPACT',
}

function KillChain({ killchain }) {
  const [open, setOpen] = useState(null)
  const achievedMap = {}
  for (const a of killchain.achieved || []) achievedMap[a.tactic] = a

  return (
    <div className="px-5 py-3 border-t border-slate-800/50 bg-black/20">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] tracking-widest text-slate-500">MITRE ATT&CK KILL-CHAIN PROGRESSION</span>
        <span className="text-[10px] text-emerald-400">{killchain.stages_reached}/{killchain.total_stages} stages</span>
      </div>
      <div className="flex gap-[2px] overflow-x-auto pb-1">
        {(killchain.tactics_order || []).map((tactic) => {
          const hit = achievedMap[tactic]
          const isHit = !!hit
          return (
            <button key={tactic}
                    onClick={() => setOpen(open === tactic ? null : (isHit ? tactic : open))}
                    aria-expanded={isHit ? open === tactic : undefined}
                    aria-label={isHit
                      ? `${tactic} attack stage — ${hit.techniques.map((t) => t.name).join(', ')}`
                      : `${tactic} attack stage (no evidence)`}
                    title={isHit ? hit.techniques.map((t) => `${t.id} ${t.name}`).join('\n') : tactic}
                    className={classNames(
                      'relative flex-1 min-w-[54px] px-1 py-1.5 rounded-sm text-[8px] font-bold tracking-wide transition-all',
                      isHit
                        ? 'bg-gradient-to-b from-orange-500 to-red-600 text-white animate-pulse'
                        : 'bg-slate-800/60 text-slate-600 hover:bg-slate-800')}>
              {TACTIC_SHORT[tactic] || tactic.slice(0, 6).toUpperCase()}
              {isHit && (
                <span className="absolute top-0 right-0.5 text-[7px] text-white/90">✓{hit.evidence_count}</span>
              )}
            </button>
          )
        })}
      </div>
      {open && achievedMap[open] && (
        <div className="mt-2 p-2 bg-slate-900/80 border border-slate-700 rounded text-[11px] space-y-1">
          <div className="text-slate-400 uppercase text-[9px] tracking-widest">{open} — evidence-backed techniques</div>
          {achievedMap[open].techniques.map((t) => (
            <div key={t.id}><span className="text-red-400 font-bold">{t.id}</span> <span className="text-slate-200">{t.name}</span></div>
          ))}
          <div className="text-slate-500 text-[10px]">{achievedMap[open].evidence_count} correlated evidence events support this stage.</div>
        </div>
      )}
    </div>
  )
}

// M4 item 7: rule-vs-ML agreement counts — pure UI over data both halves
// already produce (incidents from the correlator, anomalies from the ML model).
function RuleVsMlPanel({ incidents, ml }) {
  const anomalousIds = new Set((ml.anomalies || []).map((a) => a.event_id))
  const withAnomalousEvidence = incidents.filter(
    (inc) => (inc.evidence_event_ids || []).some((id) => anomalousIds.has(id)),
  )
  const withMlReason = incidents.filter(
    (inc) => (inc.reasons || []).some((r) => /ML anomaly signal/i.test(r)),
  )
  const agreed = new Set([...withAnomalousEvidence, ...withMlReason])
  const rulesOnly = incidents.length - agreed.size
  const tiles = [
    { label: 'RULES ONLY', value: Math.max(0, rulesOnly), tone: 'text-sky-300' },
    { label: 'ML ONLY', value: ml.summary?.n_anomalies || 0, tone: 'text-purple-300' },
    { label: 'BOTH AGREED', value: agreed.size, tone: 'text-emerald-300' },
  ]
  return (
    <section className="mb-5 border border-slate-800 bg-slate-900/60 rounded-lg p-4" aria-label="Rule versus ML agreement">
      <div className="text-[10px] tracking-widest text-slate-500 mb-3">RULES vs ML — WHO SAW WHAT</div>
      <div className="grid grid-cols-3 gap-3 max-w-md">
        {tiles.map((t) => (
          <div key={t.label} className="text-center">
            <div className={`text-2xl font-bold font-mono ${t.tone}`}>{t.value}</div>
            <div className="text-[10px] tracking-widest text-slate-500 mt-1">{t.label}</div>
          </div>
        ))
        }
      </div>
      <p className="mt-3 text-[11px] text-slate-500">
        Rules-only = incidents whose evidence contains no ML-flagged events. ML only = events the
        IsolationForest flagged that no incident covers. Both agreed = incidents backed by at least
        one anomalous evidence event or an explicit ML risk bump.
      </p>
    </section>
  )
}

// Workstream A/E: deterministic "what was found" / OPSEC attribution views.
function stripTags(html) {
  return (html || '').replace(/<[^>]+>/g, '')
}

const SEV_TONE = {
  CRITICAL: 'text-red-300 border-red-800',
  HIGH: 'text-orange-300 border-orange-800',
  MEDIUM: 'text-amber-300 border-amber-800',
  LOW: 'text-sky-300 border-sky-800',
}

function PostureRing({ score }) {
  const color = score >= 70 ? '#ef4444' : score >= 40 ? '#f97316' : '#eab308'
  return (
    <div className="w-14 h-14 rounded-full grid place-items-center shrink-0"
         style={{ background: `conic-gradient(${color} ${Math.min(100, score || 0) * 3.6}deg, #374151 0deg)` }}>
      <div className="w-11 h-11 rounded-full bg-bg-base grid place-items-center">
        <span className="text-sm font-bold" style={{ color }}>{score || 0}</span>
      </div>
    </div>
  )
}

function OpsecView({ jobId, opsec, knowledge, loading }) {
  if (loading && !opsec) {
    return <div className="mt-4"><Skeleton rows={6} /></div>
  }
  if (!opsec || opsec.n_actors === 0) {
    return (
      <div className="text-sm text-slate-500 border border-slate-800 rounded p-4 bg-slate-900/40">
        No actor clusters for this dataset — OPSEC attribution requires at least two incidents
        linked by shared evidence signals.
      </div>
    )
  }
  return (
    <div className="space-y-4">
      <section className="border border-slate-800 bg-slate-900/60 rounded-lg p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-[10px] tracking-widest text-slate-500">ACTOR ATTRIBUTION — KNOWLEDGE GRAPH COMMUNITIES</div>
            <div className="text-lg font-bold mt-1 text-slate-100">
              {opsec.n_actors} actor cluster{opsec.n_actors === 1 ? '' : 's'} · {opsec.n_incidents} incidents
              <span className="ml-2 text-[11px] font-normal text-slate-500">
                link threshold {opsec.link_threshold} · mean posture {opsec.posture_summary.mean}
              </span>
            </div>
          </div>
          <button onClick={() => downloadKnowledgeGraph(jobId, knowledge)}
                  className="btn btn-ghost px-3 py-1.5 text-[11px]" title="Download GraphRAG-ready JSON">
            ⬇ EXPORT KNOWLEDGE GRAPH (GRAPHRAG JSON)
          </button>
        </div>
        <p className="mt-2 text-[11px] text-slate-500">
          Actors are the union-find communities detected on the knowledge graph — incidents linked by
          reused IOCs, shared MITRE techniques, matching geo ranges or beacon cadence.
          <a className="text-emerald-400 hover:underline" href={`#graph-${jobId}`}> Scroll to the mini-graph below.</a>
        </p>
      </section>

      <ActorKnowledgeGraph jobId={jobId} data={knowledge} />

      {opsec.actors.map((actor) => (
        <ActorCard key={actor.actor_id} actor={actor} />
      ))}
    </div>
  )
}

function ActorCard({ actor }) {
  const [open, setOpen] = useState(false)
  const iocs = actor.shared_signals?.reused_iocs || []
  const techs = actor.shared_signals?.mitre_techniques || []
  return (
    <div className="border border-emerald-900/60 rounded-lg overflow-hidden bg-slate-900/40">
      <div className="px-5 py-3 flex items-center justify-between bg-black/20">
        <div>
          <div className="text-[10px] tracking-widest text-emerald-400">{actor.actor_id}</div>
          <div className="font-bold tracking-wide mt-0.5">
            {actor.n_incidents} incident{actor.n_incidents === 1 ? '' : 's'} · {Math.round((actor.confidence || 0) * 100)}% link confidence
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] tracking-widest text-slate-500">POSTURE</span>
          <PostureRing score={actor.posture} />
        </div>
      </div>

      {actor.description && (
        <div className="px-5 py-3 border-t border-emerald-900/40">
          <div className="text-[10px] uppercase tracking-widest text-emerald-400 mb-1">What was found</div>
          <div className="text-[11px] text-slate-200 leading-relaxed">{stripTags(actor.description.summary)}</div>
        </div>
      )}

      <div className="px-5 py-3 border-t border-emerald-900/40">
        <div className="text-[10px] tracking-widest text-slate-500 mb-2">LINKED INCIDENTS</div>
        <div className="flex flex-wrap gap-2">
          {actor.members.map((m) => (
            <span key={m.id} className={classNames('px-2 py-1 rounded border text-[11px]',
              SEV_TONE[m.severity] || SEV_TONE.LOW)} title={`${m.title} · risk ${m.risk_score} · ${m.classification}`}>
              {m.entity}
            </span>
          ))}
        </div>
      </div>

      <div className="px-5 py-3 border-t border-emerald-900/40 grid md:grid-cols-2 gap-4">
        <div>
          <div className="text-[10px] tracking-widest text-slate-500 mb-1">SHARED SIGNALS</div>
          {iocs.length === 0 && techs.length === 0 && (
            <div className="text-[11px] text-slate-600">No extracted shared indicators on the links.</div>
          )}
          {iocs.length > 0 && (
            <ul className="space-y-1 mb-2">
              {iocs.map((i) => (
                <li key={i.value} className="text-[11px] text-slate-300">
                  <span className="text-amber-300">🛰 {i.value}</span>
                  <span className="text-slate-600"> — reused by {i.incidents} incident(s)</span>
                </li>
              ))}
            </ul>
          )}
          {techs.length > 0 && (
            <ul className="space-y-1">
              {techs.map((t) => (
                <li key={t.id} className="text-[11px] text-purple-300">{t.id} {t.name}</li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <button onClick={() => setOpen(!open)} aria-expanded={open}
                  className="text-[10px] tracking-widest text-slate-500 hover:text-emerald-300">
            POSTURE BREAKDOWN {open ? '▾' : '▸'}
          </button>
          {open && (
            <ul className="mt-2 space-y-1.5">
              {(actor.posture_breakdown || []).map((b, i) => (
                <li key={i} className="flex gap-2 text-[11px]">
                  <span className="text-emerald-400 font-mono shrink-0 w-5 text-right">+{b.points}</span>
                  <span className="text-slate-300">{b.reason}</span>
                  <span className={classNames('shrink-0 text-[9px] border rounded px-1 my-auto',
                    b.provenance === 'EXTRACTED' ? 'text-emerald-400 border-emerald-800' : 'text-slate-500 border-slate-700')}>
                    {b.provenance}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  )
}

function downloadKnowledgeGraph(jobId, data) {
  if (!data) return
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `knowledge-${jobId}.json`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

const NODE_STYLE = {
  incident: { color: '#ef4444', shape: 'hexagon' },
  technique: { color: '#a855f7', shape: 'round-rectangle' },
  ioc: { color: '#f59e0b', shape: 'diamond' },
  entity: { color: '#3b82f6', shape: 'ellipse' },
}
const COMMUNITY_PALETTE = ['#10b981', '#f97316', '#818cf8', '#14b8a6', '#e879f9', '#22d3ee']

function ActorKnowledgeGraph({ jobId, data }) {
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const cyModRef = useRef(null)
  const [cyReady, setCyReady] = useState(false)

  useEffect(() => {
    let cancelled = false
    import('cytoscape').then((m) => {
      cyModRef.current = m.default
      if (!cancelled) setCyReady(true)
    })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (!data || !containerRef.current || !cyModRef.current) return
    if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null }

    const communityColor = new Map()
    let next = 0
    const colorFor = (community) => {
      if (!community) return null
      if (!communityColor.has(community)) {
        communityColor.set(community, COMMUNITY_PALETTE[next % COMMUNITY_PALETTE.length])
        next += 1
      }
      return communityColor.get(community)
    }

    const elements = []
    for (const n of data.nodes || []) {
      const s = NODE_STYLE[n.type] || NODE_STYLE.entity
      const border = colorFor(n.community)
      elements.push({
        data: {
          id: n.id, label: n.label,
          color: s.color,
          shape: s.shape,
          size: n.type === 'incident' ? 20 + Math.min(22, (n.meta?.risk_score || 0) / 3)
            : n.type === 'ioc' ? 12 : 11,
          border,
        },
      })
    }
    for (const e of data.edges || []) {
      elements.push({
        data: {
          source: e.source, target: e.target,
          color: e.kind === 'EXTRACTED' ? '#334155' : '#f97316',
          width: e.kind === 'EXTRACTED' ? 1 : 0.5 + (e.confidence || 0.5) * 2,
          dashed: e.kind !== 'EXTRACTED',
          label: e.label,
        },
      })
    }

    const cy = cyModRef.current({
      container: containerRef.current,
      elements,
      style: [
        { selector: 'node', style: {
            'background-color': 'data(color)', label: 'data(label)',
            width: 'data(size)', height: 'data(size)', shape: 'data(shape)',
            color: '#cbd5e1', 'font-size': 7, 'text-valign': 'bottom', 'text-margin-y': 3,
        } },
        { selector: 'node[?border]', style: {
            'border-width': 2, 'border-color': 'data(border)',
        } },
        { selector: 'edge', style: {
            width: 'data(width)', 'line-color': 'data(color)',
            'line-style': 'data(dashed)', 'curve-style': 'bezier', opacity: 0.75,
            'target-arrow-shape': 'triangle', 'target-arrow-color': 'data(color)',
        } },
      ],
      layout: { name: 'cose', animate: true, padding: 20, idealEdgeLength: () => 70 },
      wheelSensitivity: 0.2,
      minZoom: 0.15,
    })
    cyRef.current = cy
    cy.fit()
    return () => { if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null } }
  }, [data, cyReady])

  if (!data || !data.nodes || data.nodes.length === 0) {
    return null
  }
  const communities = data.summary?.communities || []
  return (
    <section id={`graph-${jobId}`} className="border border-emerald-800/60 rounded-lg overflow-hidden bg-slate-950/50"
             aria-label="Job knowledge graph">
      <div className="flex items-center justify-between px-4 py-2 border-b border-emerald-900/50 bg-black/20">
        <span className="text-[10px] tracking-widest text-emerald-400">
          JOB KNOWLEDGE GRAPH — {data.nodes.length} NODES · {data.edges.length} EDGES · {data.summary?.n_communities || 0} COMMUNITIES
        </span>
        <div className="flex gap-3 text-[9px] text-slate-500">
          {Object.entries({ INC: 'incident', TTP: 'technique', IOC: 'ioc', ENT: 'entity' }).map(([k, v]) => (
            <span key={v} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-sm inline-block" style={{ background: NODE_STYLE[v].color }} />
              {k}
            </span>
          ))}
          <span className="flex items-center gap-1">
            <span className="w-3 border-t-2 border-dashed border-orange-500 inline-block" /> INFERRED
          </span>
        </div>
      </div>
      <div ref={containerRef} className="h-[360px]"
           role="img"
           aria-label={`Knowledge graph with ${data.nodes.length} nodes and ${data.edges.length} edges`} />
      {communities.length > 0 && (
        <div className="px-4 py-2 border-t border-emerald-900/50 text-[9px] text-slate-500 flex flex-wrap gap-x-4 gap-y-1">
          {communities.slice(0, 8).map((c, i) => (
            <span key={c.id} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full inline-block"
                    style={{ background: COMMUNITY_PALETTE[i % COMMUNITY_PALETTE.length] }} />
              {c.id} · {c.n_nodes} nodes
            </span>
          ))}
        </div>
      )}
    </section>
  )
}

// M5 item 3: SOAR-lite — per-action "Simulate" buttons + simulated-action history.
function RecommendedResponse({ inc, simulate, canAct }) {
  const { data: history } = useQuery({
    queryKey: ['threat-actions', inc.id],
    queryFn: () => api(`/incidents/${inc.id}/actions`).then((d) => d.actions),
    enabled: !!(inc.recommended_actions && inc.recommended_actions.length),
  })
  const actions = inc.recommended_actions || []
  if (actions.length === 0) return null

  return (
    <div className="px-5 py-3 border-t border-sky-900/40 bg-sky-950/10">
      <div className="text-[10px] tracking-widest text-sky-400 mb-2">RECOMMENDED RESPONSE · PLAYBOOK</div>
      <ul className="space-y-2">
        {actions.map((a) => (
          <li key={a.id} className="flex items-start gap-3">
            <div className="text-xs flex-1">
              <span className="font-mono text-[10px] text-sky-300 bg-sky-950/60 border border-sky-900 rounded px-1 mr-2">{a.id}</span>
              <span className="text-slate-200">{a.label}</span>
              <div className="text-[11px] text-slate-400 mt-0.5">{a.reason}</div>
            </div>
            <button
              onClick={() => simulate.mutate({ id: inc.id, actionId: a.id })}
              disabled={!canAct || simulate.isPending}
              title={canAct ? `Record a SIMULATED run of ${a.id}` : 'requires analyst or above'}
              className="btn btn-ghost px-3 py-1.5 text-[11px] whitespace-nowrap disabled:cursor-not-allowed disabled:opacity-40">
              SIMULATE
            </button>
          </li>
        ))}
      </ul>
      {history && history.length > 0 && (
        <div className="mt-3">
          <div className="text-[10px] tracking-widest text-slate-500 mb-2">SIMULATED-ACTION HISTORY</div>
          <ul className="space-y-1.5 border border-slate-800/70 rounded p-2 bg-black/20 max-h-28 overflow-auto">
            {history.map((h) => (
              <li key={h.id} className="text-[11px] flex flex-wrap items-center gap-x-3 gap-y-0.5">
                <span className="font-mono text-[10px] text-sky-300">{h.action_id}</span>
                <span className="text-slate-400">by {h.actor}</span>
                <span className="text-slate-500">{h.created_at ? h.created_at.replace('T', ' ').slice(0, 19) : ''}</span>
                <span className="text-emerald-400">{h.outcome}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}