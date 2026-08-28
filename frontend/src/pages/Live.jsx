import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import PageHeader from '../components/PageHeader.jsx'
import { api, classNames } from '../lib/api.js'

const SEV_STYLE = {
  LOW: 'text-blue-400 border-blue-800',
  MEDIUM: 'text-yellow-400 border-yellow-700',
  HIGH: 'text-orange-400 border-orange-700',
  CRITICAL: 'text-red-400 border-red-700',
}

const SEV_BAR = {
  LOW: 'bg-blue-500',
  MEDIUM: 'bg-yellow-400',
  HIGH: 'bg-orange-500',
  CRITICAL: 'bg-red-500',
}

export default function Live() {
  const queryClient = useQueryClient()
  const [autoScroll, setAutoScroll] = useState(true)
  const wallRef = useRef(null)

  const { data: recents } = useQuery({
    queryKey: ['stream', 'recent'],
    queryFn: () => api('/stream/recent?limit=100'),
    refetchInterval: 1500,
  })

  const { data: status } = useQuery({
    queryKey: ['stream', 'status'],
    queryFn: () => api('/stream/status'),
    refetchInterval: 1500,
  })

  const start = useMutation({
    mutationFn: () => api(`/stream/start?interval_ms=1000&lines_per_tick=5`, { method: 'POST', body: '{}' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['stream'] })
      queryClient.invalidateQueries({ queryKey: ['jobs'] })
    },
  })

  const stop = useMutation({
    mutationFn: () => api('/stream/stop', { method: 'POST', body: '{}' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['stream'] })
      queryClient.invalidateQueries({ queryKey: ['jobs'] })
    },
  })

  useEffect(() => {
    if (!autoScroll) return
    if (!recents?.running && !recents?.events?.length) return
    wallRef.current?.scrollTo({ top: wallRef.current.scrollHeight, behavior: 'smooth' })
  }, [recents?.events?.length, autoScroll, recents?.running])

  const events = recents?.events || []
  const running = Boolean(recents?.running)

  return (
    <div className="p-4 md:p-6 lg:p-8">
      <PageHeader title="EVENT WALL" subtitle="Live event stream as it hits the pipeline — watch detection, correlation and alerting fire in real time." />

      <div className="flex flex-wrap items-center gap-3 mb-4">
        {!running ? (
          <button onClick={() => start.mutate()} disabled={start.isPending}
                  className="btn btn-primary px-4 py-2 text-xs">▶ START STREAM</button>
        ) : (
          <button onClick={() => stop.mutate()} disabled={stop.isPending}
                  className="btn btn-danger px-4 py-2 text-xs">■ STOP STREAM</button>
        )}
        <span className={classNames('px-2 py-1 rounded text-[10px] tracking-widest border',
          running ? 'text-red-300 border-red-800 bg-red-950/30' : 'text-slate-500 border-slate-700')}>
          {running ? '● LIVE' : '○ STANDBY'}
        </span>
        <span className="text-[10px] text-slate-500">
          {recents?.lines_emitted ?? 0} lines · job {recents?.job_id?.slice(0, 8) || '—'}
        </span>
        <label className="flex items-center gap-2 text-[11px] text-slate-400 ml-auto">
          <input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)}
                 aria-label="Auto-scroll to newest events" />
          auto-scroll
        </label>
      </div>

      <div ref={wallRef} tabIndex={0} className="h-[60vh] overflow-y-auto border border-slate-800 rounded-lg bg-slate-950/40 focus:outline-none focus:ring-2 focus:ring-emerald-600/40"
           aria-label="Live event wall">
        {events.length === 0 && (
          <div className="p-8 text-center text-sm text-slate-500">
            No events yet. Start a stream or the wall will show the most recent dataset.
          </div>
        )}
        {events.map((e) => (
          <div key={e.event_id} className="flex border-b border-slate-800/50 text-xs">
            <span className={classNames('shrink-0 w-1', SEV_BAR[e.severity] || 'bg-slate-600')} aria-hidden="true" />
            <div className="flex-1 px-3 py-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 min-w-0">
              <span className="text-slate-500 whitespace-nowrap text-[10px]">
                {(e.ts || '—').replace('T', ' ').slice(0, 19)}
              </span>
              <span className="text-slate-300 whitespace-nowrap">{e.source || '—'}</span>
              <span className="text-slate-400 whitespace-nowrap">{e.event_type}</span>
              <span className="text-sky-300 whitespace-nowrap">{e.src_ip || ''}</span>
              <span className="text-slate-400 text-[10px]">{e.dst_ip ? `→ ${e.dst_ip}` : ''}</span>
              <span className={classNames('px-1.5 py-0.5 border rounded text-[10px]', SEV_STYLE[e.severity])}>
                {e.severity}
              </span>
              {e.threat_type && <span className="text-red-300 text-[10px]">{e.threat_type}</span>}
              <span className="text-slate-300 truncate flex-1 min-w-0">{e.message}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}