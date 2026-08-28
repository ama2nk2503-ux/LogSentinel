import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import PageHeader from '../components/PageHeader.jsx'
import Skeleton from '../components/Skeleton.jsx'
import { api, classNames } from '../lib/api.js'

const CLASS_STYLE = {
  MALICIOUS: 'border-red-700 bg-red-950/30 text-red-300',
  SUSPICIOUS: 'border-orange-700 bg-orange-950/20 text-orange-300',
  BENIGN: 'border-slate-700 bg-slate-900/40 text-slate-400',
}

export default function Threats() {
  const [jobId, setJobId] = useState('')

  const { data } = useQuery({
    queryKey: ['threats', jobId],
    queryFn: () => api(`/threats/${jobId}`),
    enabled: !!jobId,
  })

  useEffect(() => { }, [jobId])

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
          <div key={inc.entity + inc.title} className={classNames('border rounded-lg overflow-hidden', CLASS_STYLE[inc.classification])}>
            <div className="px-5 py-3 flex items-center justify-between">
              <div>
                <div className="font-bold tracking-wide">{inc.title}</div>
                <div className="text-[11px] opacity-70 mt-0.5">
                  entity <b>{inc.entity}</b> · {inc.category} · {inc.classification}
                </div>
              </div>
              <RiskRing score={inc.risk_score} severity={inc.severity} />
            </div>

            {inc.killchain && inc.killchain.tactics_order && (
              <KillChain killchain={inc.killchain} />
            )}

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
