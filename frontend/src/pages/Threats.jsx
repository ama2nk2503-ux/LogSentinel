import { useEffect, useId, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import PageHeader from '../components/PageHeader.jsx'
import Skeleton from '../components/Skeleton.jsx'
import { api, classNames } from '../lib/api.js'

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
  const queryClient = useQueryClient()

  const { data } = useQuery({
    queryKey: ['threats', jobId],
    queryFn: () => api(`/threats/${jobId}`),
    enabled: !!jobId,
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

  return (
    <div className="p-4 md:p-6 lg:p-8">
      <PageHeader title="THREAT CORRELATION" />
      <div className="mb-5"><JobPicker value={jobId} onChange={setJobId} /></div>

      {!jobId && <div className="text-sm text-slate-500">Select a processed dataset.</div>}

      {jobId && !data && <Skeleton rows={5} className="mt-4" />}

      {data && data.incidents.length === 0 && (
        <div className="text-sm text-emerald-500 border border-emerald-900 rounded p-4 bg-emerald-950/20">
          ✓ No threat incidents correlated for this dataset.
        </div>
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