import { useEffect, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import PageHeader from '../components/PageHeader.jsx'
import { api } from '../lib/api.js'

const FALLBACK = 'unknown — generic fallback'

function Tile({ label, value, tone = 'emerald' }) {
  const tones = {
    emerald: 'text-emerald-400',
    sky: 'text-sky-400',
    amber: 'text-amber-400',
    red: 'text-red-400',
    purple: 'text-purple-400',
  }
  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded p-3">
      <div className="text-[10px] tracking-widest text-slate-500 mb-1">{label}</div>
      <div className={`text-xl font-bold font-mono ${tones[tone]}`}>{value}</div>
    </div>
  )
}

export default function ParserLab() {
  const [text, setText] = useState('')
  const [debounced, setDebounced] = useState('')

  // Debounce live parsing so typing doesn't spam the API
  useEffect(() => {
    const t = setTimeout(() => setDebounced(text), 400)
    return () => clearTimeout(t)
  }, [text])

  const parse = useMutation({
    mutationFn: () => api('/parserlab/parse', {
      method: 'POST',
      body: JSON.stringify({ text: debounced }),
    }),
  })

  useEffect(() => {
    if (debounced.trim()) parse.mutate()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced])

  const data = parse.data
  const s = data?.summary

  return (
    <div className="p-4 md:p-6 lg:p-8">
      <PageHeader
        title="PARSER LAB"
        subtitle="Live parsing against the real engine — nothing is stored"
      />

      <div className="grid lg:grid-cols-2 gap-4">
        <div>
          <label htmlFor="parserlab-input" className="block text-xs tracking-widest text-slate-500 mb-2">
            PASTE RAW LOG LINES
          </label>
          <textarea
            id="parserlab-input"
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={18}
            placeholder={'%ASA-6-302013: Built inbound TCP connection 1 for outside:5.6.7.8/443 to inside:10.1.1.5/5000\ndate=2026-08-25 time=10:30:01 devname=FW1 action=deny srcip=1.2.3.4 dstip=5.6.7.8 dstport=22 proto=6\nAug 25 10:30:01 srv01 sshd[123]: Failed password for admin from 185.23.45.67 port 5000 ssh2'}
            className="w-full bg-slate-950 border border-slate-800 rounded p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-emerald-700"
          />
          <p className="mt-2 text-[11px] text-slate-600">
            Parsed with the same detector + parser registry as Upload — read-only, nothing written to the database.
          </p>
        </div>

        <div>
          <div className="text-xs tracking-widest text-slate-500 mb-2">RESULTS</div>
          {data && (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
                <Tile label="RECORDS" value={s.records} />
                <Tile
                  label="NAMED PARSER %"
                  value={`${s.named_parser_pct}%`}
                  tone={s.named_parser_pct >= 80 ? 'emerald' : s.named_parser_pct >= 50 ? 'amber' : 'red'}
                />
                <Tile label="FALLBACK %" value={`${s.fallback_pct}%`} tone={s.fallback_pct > 0 ? 'amber' : 'emerald'} />
                <Tile label="DISTINCT FORMATS" value={s.distinct_formats} tone="sky" />
              </div>

              <div className="flex flex-wrap gap-3 text-[11px] text-slate-400 mb-3">
                <span>detected: <span className="text-white font-mono">{data.detected_format}</span></span>
                <span>confidence: <span className="text-white font-mono">{Math.round((data.confidence || 0) * 100)}%</span></span>
                <span>throughput: <span className="text-white font-mono">{s.lines_per_second?.toLocaleString()} lines/s</span></span>
              </div>

              <div className="border border-slate-800 rounded overflow-auto max-h-[28rem]">
                <table className="w-full text-xs min-w-[640px]" aria-label="Per-line parser results">
                  <thead className="bg-slate-900/80 text-slate-500 tracking-wider sticky top-0">
                    <tr>
                      <th className="px-2 py-2 text-left font-normal w-10">#</th>
                      <th className="px-2 py-2 text-left font-normal">PARSER</th>
                      <th className="px-2 py-2 text-left font-normal">RAW → NORMALIZED</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.lines.map((ln) => (
                      <tr key={ln.line_no} className="border-t border-slate-800/60 align-top">
                        <td className="px-2 py-2 text-slate-500 font-mono">{ln.line_no}</td>
                        <td className={`px-2 py-2 font-mono whitespace-nowrap ${ln.parser === FALLBACK || ln.parser === 'unparsed' ? 'text-amber-400' : ln.parser === 'blank' ? 'text-slate-600' : 'text-emerald-400'}`}>
                          {ln.parser}
                        </td>
                        <td className="px-2 py-2">
                          <div className="text-slate-400 font-mono truncate max-w-[22rem]" title={ln.raw}>{ln.raw}</div>
                          {ln.fields && (
                            <div className="mt-1 flex flex-wrap gap-1">
                              {Object.entries(ln.fields).slice(0, 8).map(([k, v]) => (
                                <span key={k} className="px-1.5 py-0.5 bg-slate-800/80 rounded text-[10px] font-mono text-sky-300">
                                  {k}={String(v).slice(0, 40)}
                                </span>
                              ))}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {!data && !parse.isPending && !debounced.trim() && (
            <div className="text-sm text-slate-500 border border-dashed border-slate-800 rounded p-8 text-center">
              Type or paste log lines — parsing starts automatically.
            </div>
          )}
          {parse.isPending && debounced.trim() && (
            <div className="text-sm text-slate-500 p-4">Parsing…</div>
          )}
        </div>
      </div>
    </div>
  )
}
