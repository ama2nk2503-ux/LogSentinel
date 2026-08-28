import { useEffect, useId, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import PageHeader from '../components/PageHeader.jsx'
import Skeleton from '../components/Skeleton.jsx'
import { api, classNames } from '../lib/api.js'
import useQueryParam from '../lib/useQueryParam.js'
import useDebouncedValue from '../lib/useDebouncedValue.js'

const SEV_STYLE = {
  LOW: 'text-blue-400 border-blue-800',
  MEDIUM: 'text-yellow-400 border-yellow-700',
  HIGH: 'text-orange-400 border-orange-700',
  CRITICAL: 'text-red-400 border-red-700',
}

export default function Explorer() {
  const [jobId, setJobId] = useQueryParam('job', '')
  const [q, setQ] = useQueryParam('q', '')
  const [severity, setSeverity] = useQueryParam('severity', '')
  const [threat, setThreat] = useQueryParam('threat', '')
  const [page, setPage] = useQueryParam('page', '1')
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const lastFocused = useRef(null)

  const debouncedQ = useDebouncedValue(q)
  const debouncedThreat = useDebouncedValue(threat)

  const { data } = useQuery({
    queryKey: ['events', jobId, debouncedQ, debouncedThreat, severity, page],
    queryFn: () => {
      const params = new URLSearchParams({ job_id: jobId, page: String(page), page_size: '50' })
      if (debouncedQ) params.set('q', debouncedQ)
      if (severity) params.set('severity', severity)
      if (debouncedThreat) params.set('threat', debouncedThreat)
      return api(`/events?${params}`)
    },
    enabled: !!jobId,
  })

  useEffect(() => { setPage('1'); setSelected(null); setDetail(null) }, [jobId])

  async function openDetail(eventId) {
    lastFocused.current = document.activeElement
    setSelected(eventId)
    try { setDetail(await api(`/events/${eventId}`)) } catch { setDetail(null) }
  }

  function closeDetail() {
    setSelected(null)
    setDetail(null)
    lastFocused.current?.focus?.()
  }

  const totalPages = data ? Math.max(1, Math.ceil(data.total / 50)) : 1

  return (
    <div className="p-4 md:p-6 lg:p-8">
      <PageHeader title="LOG EXPLORER" />

      <div className="flex flex-wrap gap-3 items-center mb-4">
        <JobPicker value={jobId} onChange={setJobId} />
        <input
          value={q} onChange={(e) => setQ(e.target.value)} placeholder="search ip / user / message…"
          aria-label="Search events"
          className="input w-full md:w-64"
        />
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}
                aria-label="Severity filter" className="input">
          <option value="">all severities</option>
          {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => <option key={s}>{s}</option>)}
        </select>
        <input value={threat} onChange={(e) => setThreat(e.target.value)} placeholder="threat type"
               aria-label="Threat type filter" className="input w-full md:w-40" />
      </div>

      {!jobId && <div className="text-sm text-slate-500">Select a processed dataset to explore events.</div>}

      {jobId && !data && <Skeleton rows={8} className="mt-4" />}

      {data && (
        <>
          <div className="border border-slate-800 rounded overflow-x-auto">
            <table className="w-full text-xs min-w-[640px]" aria-label="Event log entries">
              <thead className="bg-slate-900/80 text-slate-500 tracking-wider">
                <tr>
                  {['TIME', 'SOURCE', 'TYPE', 'SRC IP', 'DST IP', 'THREAT', 'SEV', 'IOC', 'PII', 'RISK'].map((h) => (
                    <th key={h} className="px-3 py-2 text-left font-normal whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.events.map((e) => (
                  <tr key={e.id}
                      onClick={() => openDetail(e.event_id)}
                      tabIndex={0}
                      aria-label={`View details for event from ${e.source || 'unknown'} at ${e.ts || ''}`}
                      onKeyDown={(ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); openDetail(e.event_id) } }}
                      className={classNames(
                        'cursor-pointer border-t border-slate-800/60 hover:bg-slate-800/30',
                        selected === e.event_id && 'bg-emerald-500/10',
                      )}>
                    <td className="px-3 py-1.5 text-slate-400 whitespace-nowrap">{(e.ts || '').replace('T', ' ').slice(0, 19)}</td>
                    <td className="px-3 py-1.5 text-slate-300 whitespace-nowrap">{e.source}</td>
                    <td className="px-3 py-1.5 text-slate-300 whitespace-nowrap">{e.event_type}</td>
                    <td className="px-3 py-1.5 text-sky-300 whitespace-nowrap">{e.src_ip}</td>
                    <td className="px-3 py-1.5 text-slate-400 whitespace-nowrap">{e.dst_ip}</td>
                    <td className="px-3 py-1.5 text-red-300 whitespace-nowrap">{e.threat_type}</td>
                    <td className="px-3 py-1.5 whitespace-nowrap">
                      <span className={classNames('px-1.5 py-0.5 border rounded text-[10px]', SEV_STYLE[e.severity])}>
                        {e.severity}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-purple-300">{e.iocs?.length ? `${e.iocs.length}` : ''}</td>
                    <td className="px-3 py-1.5 text-amber-300">{e.pii?.length ? `${e.pii.length}` : ''}</td>
                    <td className="px-3 py-1.5 font-bold text-slate-200">{e.risk_score || ''}</td>
                  </tr>
                ))}
                {data.events.length === 0 && (
                  <tr><td colSpan={10} className="px-3 py-6 text-center text-slate-600">No matching events</td></tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="flex justify-between items-center mt-3 text-xs text-slate-500">
            <span aria-live="polite">{data.total} events</span>
            <div className="flex gap-2">
              <button disabled={Number(page) <= 1} onClick={() => setPage(String(Number(page) - 1))}
                      className="px-3 py-1 border border-slate-700 rounded disabled:opacity-30 hover:border-slate-500">◀ PREV</button>
              <span className="px-2 py-1">page {page}/{totalPages}</span>
              <button disabled={Number(page) >= totalPages} onClick={() => setPage(String(Number(page) + 1))}
                      className="px-3 py-1 border border-slate-700 rounded disabled:opacity-30 hover:border-slate-500">NEXT ▶</button>
            </div>
          </div>

          {detail && <RawNormalized detail={detail} onClose={closeDetail} />}
        </>
      )}
    </div>
  )
}

function Chip({ children, tone = 'slate' }) {
  const tones = {
    slate: 'bg-slate-800 text-slate-300',
    purple: 'bg-purple-900/50 text-purple-300',
    amber: 'bg-amber-900/50 text-amber-300',
    red: 'bg-red-900/50 text-red-300',
  }
  return <span className={`px-2 py-0.5 rounded text-[10px] ${tones[tone]}`}>{children}</span>
}

function RawNormalized({ detail, onClose }) {
  const panelRef = useRef(null)
  const titleId = useId()

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
      className="mt-5 border border-emerald-900/60 rounded-lg overflow-hidden outline-none"
    >
      <div className="bg-emerald-900/20 px-4 py-2 flex justify-between items-center">
        <span id={titleId} className="text-xs tracking-widest text-emerald-400">EVENT DETAIL — RAW vs NORMALIZED</span>
        <button onClick={onClose} aria-label="Close event detail" className="text-xs text-slate-400 hover:text-white">✕ close</button>
      </div>
      <div className="grid md:grid-cols-2 gap-4 p-4 bg-slate-950/60">
        <div>
          <div className="text-[10px] tracking-widest text-slate-500 mb-2">RAW</div>
          <pre className="bg-slate-900 border border-slate-800 rounded p-3 text-[11px] text-orange-200 whitespace-pre-wrap break-all max-h-48 overflow-auto">{detail.raw_line ?? '(unavailable)'}</pre>
        </div>
        <div>
          <div className="text-[10px] tracking-widest text-slate-500 mb-2">NORMALIZED</div>
          <div className="space-y-1 text-xs">
            {[
              ['Timestamp', detail.ts], ['Event', detail.event_type],
              ['Source IP', detail.src_ip], ['Destination IP', detail.dst_ip],
              ['Username', detail.username], ['Hostname', detail.hostname],
              ['Action', detail.action], ['Status', detail.status],
              ['Severity', detail.severity], ['Threat', detail.threat_type],
            ].filter(([, v]) => v).map(([k, v]) => (
              <div key={k} className="flex gap-2">
                <span className="text-slate-600 w-24 shrink-0">{k}</span>
                <span className="text-emerald-300 break-all">{String(v)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {(detail.iocs?.length > 0 || detail.pii?.length > 0) && (
        <div className="px-4 pb-4 flex flex-wrap gap-2">
          {detail.iocs?.map((i) => (
            <Chip key={'ioc' + i.value} tone="purple">IOC · {i.type.toUpperCase()} · {i.value}</Chip>
          ))}
          {detail.pii?.map((p) => <Chip key={p} tone="amber">PII · {p}</Chip>)}
        </div>
      )}

      {Object.keys(detail.mappings || {}).length > 0 && (
        <div className="border-t border-slate-800 px-4 py-3 bg-slate-900/40">
          <div className="text-[10px] tracking-widest text-slate-500 mb-2">FIELD MAPPING PROVENANCE (raw → normalized)</div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-x-4 gap-y-1 text-[11px]">
            {Object.entries(detail.mappings).slice(0, 24).map(([k, v]) => (
              <div key={k} className="truncate"><span className="text-orange-300">{k}</span>
                <span className="text-slate-600"> → </span>
                <span className="text-emerald-300">{k in { src_ip: 1 } ? k : k}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}