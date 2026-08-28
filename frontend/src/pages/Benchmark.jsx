import { useState } from 'react'
import { memo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import PageHeader from '../components/PageHeader.jsx'
import { api } from '../lib/api.js'

const Bar = memo(function Bar({ value }) {
  const pct = Math.round((value ?? 0) * 100)
  const color = pct >= 90 ? 'bg-emerald-500' : pct >= 70 ? 'bg-yellow-500' : 'bg-orange-500'
  return (
    <div className="flex items-center gap-2 min-w-[140px]">
      <div className="flex-1 h-2 bg-slate-800 rounded overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-300 w-12 text-right">{pct}%</span>
    </div>
  )
})

const Section = memo(function Section({ title, children }) {
  return (
    <div className="border border-slate-800 rounded p-4 bg-slate-900/40">
      <div className="text-[10px] tracking-widest text-slate-500 mb-3">{title}</div>
      <div className="space-y-2">{children}</div>
    </div>
  )
})

const KV = memo(function KV({ k, v }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-slate-400">{k}</span>
      <span className="text-slate-200">{v}</span>
    </div>
  )
})

export default function Benchmark() {
  const [error, setError] = useState('')
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['benchmark'],
    queryFn: () => api('/benchmark/results'),
  })

  const runMutation = useMutation({
    mutationFn: () => api('/benchmark/run', { method: 'POST' }),
    onSuccess: (flatResult) => {
      queryClient.setQueryData(['benchmark'], { has_run: true, results: flatResult })
    },
    onError: (e) => setError(String(e.message || e)),
  })

  const running = runMutation.isPending
  const r = data?.results

  function run() {
    setError('')
    runMutation.mutate()
  }

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 lg:p-8">
        <PageHeader title="BENCHMARK" />
        <div className="mt-6 text-sm text-slate-500 animate-pulse">Loading…</div>
      </div>
    )
  }

  return (
    <div className="p-4 md:p-6 lg:p-8">
      <PageHeader title="BENCHMARK" subtitle="Every metric is computed live from labeled fixtures — nothing is hardcoded. Precision/recall measured against ground-truth annotations in samples/labeled/." />

      <button onClick={run} disabled={running}
              className="btn btn-primary px-6 py-2.5">
        {running ? 'RUNNING SUITE…' : '▶ RUN BENCHMARK'}
      </button>
      {error && <div className="mt-3 text-sm text-red-400" role="alert">{error}</div>}

      {!r && !running && (
        <div className="mt-6 text-sm text-slate-500">No benchmark has been run yet.</div>
      )}

      {r && (
        <div className="mt-6 space-y-4 max-w-4xl">
          <div className="text-[10px] tracking-widest text-slate-600">
            LAST RUN: {(r.run_at || '').replace('T', ' ').slice(0, 19)} UTC
          </div>

          {r.parsing && (
            <Section title="PARSING ACCURACY">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">Format detection</span>
                <Bar value={r.parsing.format_detection_accuracy} />
              </div>
              <KV k="Full-parse rate" v={`${((r.parsing.full_parse_rate ?? 0) * 100).toFixed(0)}%`} />
              <KV k="Datasets evaluated" v={r.parsing.datasets} />
            </Section>
          )}

          {r.ioc_extraction && (
            <Section title="IOC EXTRACTION (public indicators)">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">Precision</span>
                <Bar value={r.ioc_extraction.precision} />
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">Recall</span>
                <Bar value={r.ioc_extraction.recall} />
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">F1</span>
                <Bar value={r.ioc_extraction.f1} />
              </div>
              <KV k="TP / FP / FN" v={`${r.ioc_extraction.tp ?? 0} / ${r.ioc_extraction.fp ?? 0} / ${r.ioc_extraction.fn ?? 0}`} />
            </Section>
          )}

          {r.pii_detection && (
            <Section title="PII DETECTION">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">Precision</span>
                <Bar value={r.pii_detection.precision} />
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">Recall</span>
                <Bar value={r.pii_detection.recall} />
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">F1</span>
                <Bar value={r.pii_detection.f1} />
              </div>
              <KV k="TP / FP / FN" v={`${r.pii_detection.tp ?? 0} / ${r.pii_detection.fp ?? 0} / ${r.pii_detection.fn ?? 0}`} />
            </Section>
          )}

          {r.redaction && (
            <Section title="REDACTION EFFECTIVENESS">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-300">Values removed under REDACT-all</span>
                <Bar value={r.redaction.redaction_effectiveness} />
              </div>
              <KV k="Values checked / removed"
                  v={`${r.redaction.values_checked ?? 0} / ${r.redaction.values_removed ?? 0}`} />
            </Section>
          )}

          {r.performance && (
            <Section title="PERFORMANCE (measured)">
              <KV k="Lines processed" v={(r.performance.lines_processed ?? 0).toLocaleString()} />
              <KV k="Wall time" v={`${r.performance.wall_seconds ?? 0}s`} />
              <KV k="Throughput" v={<b className="text-emerald-400">{(r.performance.throughput_lps ?? 0).toLocaleString()} lines/sec</b>} />
              <KV k="Peak RSS" v={`${r.performance.peak_rss_mb ?? 0} MB (baseline ${r.performance.rss_baseline_mb ?? 0} MB)`} />
              <KV k="CPU (process)" v={`${r.performance.cpu_process_seconds ?? 0}s`} />
            </Section>
          )}
        </div>
      )}
    </div>
  )
}
