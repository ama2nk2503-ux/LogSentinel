import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import PageHeader from '../components/PageHeader.jsx'
import Skeleton from '../components/Skeleton.jsx'
import { api, classNames } from '../lib/api.js'
import { hasRole, useRole } from '../lib/AuthContext.jsx'

const ENTITY_TYPES = ['all', 'ip', 'hostname', 'username', 'dst_port']

export default function Baseline() {
  const queryClient = useQueryClient()
  const canMutate = hasRole('analyst', useRole())
  const [et, setEt] = useState('all')
  const [jobId, setJobId] = useState('')

  const { data: baseline } = useQuery({
    queryKey: ['baseline', et],
    queryFn: () => api(`/baseline${et === 'all' ? '' : `?entity_type=${et}`}`),
  })

  const { data: jobs } = useQuery({
    queryKey: ['jobs'],
    queryFn: () => api('/jobs').then((d) => d.jobs),
  })

  useEffect(() => {
    if (jobs?.length && !jobId) setJobId(jobs[0].id)
  }, [jobs, jobId])

  const { data: anomalies } = useQuery({
    queryKey: ['baseline-anomalies', jobId],
    queryFn: () => api(`/baseline/anomalies?job_id=${jobId}&min_z=2.0`),
    enabled: !!jobId,
  })

  const rebuild = useMutation({
    mutationFn: () => api('/baseline/rebuild', { method: 'POST' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['baseline'] })
      queryClient.invalidateQueries({ queryKey: ['baseline-anomalies'] })
    },
  })

  const stats = baseline?.stats || []
  const items = anomalies?.anomalies || []

  return (
    <div className="p-4 md:p-6 lg:p-8 space-y-6">
      <PageHeader title="ENTITY BASELINE" subtitle="Welford online mean / σ per entity across every ingested job window — anomaly scoring is always explained in plain text." />

      <div className="border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-4 py-2 flex items-center justify-between gap-3 border-b border-slate-800/70 bg-slate-950/40">
          <span className="text-[10px] tracking-widest text-slate-500">RUNNING BASELINE</span>
          <div className="flex items-center gap-2">
            <label className="text-[10px] text-slate-500" htmlFor="bl-type">ENTITY TYPE</label>
            <select id="bl-type" value={et} onChange={(e) => setEt(e.target.value)}
                    className="input" aria-label="Entity type filter">
              {ENTITY_TYPES.map((t) => <option key={t} value={t}>{t.toUpperCase()}</option>)}
            </select>
            <button onClick={() => rebuild.mutate()}
                    disabled={!canMutate || rebuild.isPending}
                    title={canMutate ? 'Re-scan every completed job' : 'requires analyst or above'}
                    className="btn btn-ghost px-3 py-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-40">
              {rebuild.isPending ? 'RE-SCANNING…' : 'RE-SCAN JOBS'}
            </button>
          </div>
        </div>
        {!baseline && <Skeleton rows={4} className="m-2" />}
        {baseline && (
          <>
            {stats.length === 0 && (
              <div className="p-4 text-sm text-slate-400">No baseline windows yet — ingest jobs or run RE-SCAN JOBS.</div>
            )}
            {stats.length > 0 && (
              <table className="w-full text-xs" aria-label="Entity baselines">
                <thead>
                  <tr>{['ENTITY TYPE', 'ENTITY', 'ATTRIBUTE', 'WINDOWS', 'MEAN', 'STD', 'CV', 'LAST VALUE'].map((h) => (
                    <th key={h} className="table-header">{h}</th>))}</tr>
                </thead>
                <tbody>
                  {stats.map((s) => (
                    <tr key={`${s.entity_type}:${s.entity}:${s.attribute}`} className="border-t border-slate-800/60">
                      <td className="table-cell text-slate-400">{s.entity_type}</td>
                      <td className="table-cell font-mono text-purple-300">{s.entity}</td>
                      <td className="table-cell text-emerald-300">{s.attribute}</td>
                      <td className="table-cell">{s.n}</td>
                      <td className="table-cell">{s.mean}</td>
                      <td className="table-cell">{s.std}</td>
                      <td className="table-cell">{s.cv}</td>
                      <td className="table-cell text-slate-400">{s.last_value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </div>

      <div className="border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-4 py-2 flex items-center justify-between gap-3 border-b border-slate-800/70 bg-slate-950/40">
          <span className="text-[10px] tracking-widest text-slate-500">ANOMALY SCAN AGAINST BASELINE (z ≥ 2.0)</span>
          <select value={jobId} onChange={(e) => setJobId(e.target.value)}
                  aria-label="Job to scan" className="input max-w-xs">
            {jobs?.map((j) => <option key={j.id} value={j.id}>{j.filename} ({j.status})</option>)}
          </select>
        </div>
        {jobId && !anomalies && <Skeleton rows={3} className="m-2" />}
        {jobId && anomalies && (
          <ul className="divide-y divide-slate-800/60 text-xs">
            {items.length === 0 && (
              <li className="px-4 py-3 text-emerald-400">No attribute crossed +2σ — traffic is within the learned baseline.</li>
            )}
            {items.map((a, i) => (
              <li key={`${a.entity}:${a.attribute}:${i}`} className="px-4 py-2.5">
                <span className={classNames('px-1.5 py-0.5 border rounded mr-2 text-[10px] font-bold',
                  a.z >= 3 ? 'text-red-300 border-red-800' : 'text-amber-300 border-amber-800')}>
                  z {a.z >= 0 ? '+' : ''}{a.z}σ
                </span>
                <span className="font-mono text-purple-300">{a.entity_type}/{a.entity}</span>
                <span className="mx-1 text-slate-500">•</span>
                <span>{a.reason}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}