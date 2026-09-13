import { useEffect, useRef, useState } from 'react'
import JobPicker from '../components/JobPicker.jsx'
import PageHeader from '../components/PageHeader.jsx'
import { api } from '../lib/api.js'

const QUICK_PROMPTS = [
  'What happened?',
  'How do I fix the brute force?',
  'Show me the high-risk authentication events',
  'List the errors found',
]

export default function Assistant() {
  const [jobId, setJobId] = useState('')
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState(null)
  const [error, setError] = useState('')
  const bottomRef = useRef(null)

  useEffect(() => {
    api('/assistant/status').then(setStatus).catch(() => {})
  }, [])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, busy])

  const send = async (q) => {
    const text = (q ?? input).trim()
    if (!text || !jobId || busy) return
    const history = messages
      .filter((m) => m.role === 'user' || m.role === 'assistant')
      .map((m) => ({ role: m.role, content: m.role === 'assistant' ? m.answer : m.content }))
    setMessages((ms) => [...ms, { role: 'user', content: text }])
    setInput('')
    setBusy(true)
    setError('')
    try {
      const r = await api('/assistant', {
        method: 'POST',
        body: JSON.stringify({ job_id: jobId, question: text, history }),
      })
      setMessages((ms) => [...ms, { role: 'assistant', ...r }])
    } catch (e) {
      setMessages((ms) => ms.slice(0, -1))
      setInput(text)
      setError(String(e?.message || e))
    } finally {
      setBusy(false)
    }
  }

  const onKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send()
    }
  }

  const toggleMode = async () => {
    if (!status) return
    const next = status.enabled ? 'off' : 'on'
    setStatus({ ...status, enabled: next === 'on', mode: next })
    try {
      const fresh = await api('/assistant/mode', {
        method: 'PATCH',
        body: JSON.stringify({ mode: next }),
      })
      setStatus(fresh)
    } catch (e) {
      setError(String(e?.message || e))
      api('/assistant/status').then(setStatus).catch(() => {})
    }
  }

  return (
    <div className="p-4 md:p-6 lg:p-8">
      <PageHeader title="AI ASSISTANT" subtitle="Session chat over one processed dataset — grounded in deterministic facts, errors, attacks, and remediation the engine computed." />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <JobPicker value={jobId} onChange={setJobId} />
        <div className="flex items-center gap-2 border border-purple-900/60 rounded px-3 py-1.5 text-[10px] font-mono tracking-widest">
          {status?.mode === 'off' ? (
            <span className="text-slate-400">○ AI OFF — deterministic evidence only</span>
          ) : status?.llm_available ? (
            <><span className="text-purple-300">● AI ON — {status.model}</span><span className="text-slate-500">({status.llm_url})</span></>
          ) : status?.mode === 'on' ? (
            <span className="text-amber-300">● AI ENABLED — deterministic only (LLM unreachable)</span>
          ) : (
            <span className="text-slate-400">● AUTO — deterministic (no local model detected)</span>
          )}
        </div>
        <button
          onClick={toggleMode}
          disabled={!status}
          aria-pressed={!!status?.enabled}
          aria-label={status?.enabled ? 'Turn AI off' : 'Turn AI on'}
          className={`px-3 py-1.5 text-[10px] font-mono tracking-widest rounded border disabled:opacity-40 ${
            status?.enabled
              ? 'border-purple-600/60 text-purple-300 hover:bg-purple-950/40'
              : 'border-slate-600/60 text-slate-400 hover:bg-slate-800/50'
          }`}
        >
          {status?.enabled ? '● AI ON' : '○ AI OFF'}
        </button>
        {status && !status.llm_available && status.mode !== 'off' && (
          <div className="text-[10px] text-slate-500">
            💡 {status.model_hint || `Install a tiny local model, e.g. a 0.5B model, to switch AI on`}
          </div>
        )}
        <button
          onClick={() => send('What attacks and errors were found, and how do I fix them?')}
          disabled={!jobId || busy}
          aria-label="Sweep for attacks and fixes"
          className="btn px-3 py-1.5 text-[11px] disabled:opacity-40"
        >
          ⚡ SWEEP — FIND ATTACKS & FIXES
        </button>
      </div>

      <div className="mb-4 flex flex-wrap gap-2 max-w-3xl">
        {QUICK_PROMPTS.map((p) => (
          <button
            key={p}
            onClick={() => send(p)}
            disabled={!jobId || busy}
            className="border border-slate-700 hover:border-emerald-600 rounded-full px-3 py-1 text-[11px] text-slate-400 hover:text-emerald-300 disabled:opacity-40"
          >
            {p}
          </button>
        ))}
      </div>

      <div className="flex flex-col h-[56vh] max-w-3xl border border-slate-800 rounded-lg bg-slate-950/60 overflow-hidden" aria-label="AI assistant conversation">
        <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
          {messages.length === 0 && !busy && (
            <div className="text-xs text-slate-500 max-w-md">
              Select a dataset, then ask anything about its logs: which incidents
              were found and why, error health, or how to fix a specific attack —
              e.g. “what was the risk score of the brute force?”.
            </div>
          )}

          {messages.map((m, i) =>
            m.role === 'user' ? (
              <div key={i} className="self-end max-w-[75%] bg-emerald-900/40 border border-emerald-800 rounded-lg px-3 py-2 text-[12px] text-emerald-200 whitespace-pre-wrap">
                {m.content}
              </div>
            ) : (
              <div key={i} className="self-start max-w-[85%] w-full sm:w-auto">
                <div className="bg-slate-900 border border-purple-800 rounded-lg px-3 py-2 text-[12px] text-slate-200 whitespace-pre-wrap">
                  {m.answer}
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px]" data-testid="ai-answer">
                  <span className={`px-1.5 py-0.5 rounded font-mono tracking-wider ${m.source === 'local_llm' ? 'bg-purple-950 text-purple-300 border border-purple-700' : 'bg-slate-800 text-slate-400 border border-slate-700'}`}>
                    {m.source === 'local_llm' ? 'LOCAL LLM' : 'DETERMINISTIC'}
                  </span>
                  <span className="text-purple-300/80">⚠ {m.disclaimer}</span>
                  <details className="inline-block">
                    <summary className="cursor-pointer text-slate-500 hover:text-slate-300">EVIDENCE / FACTS USED ({m.facts?.length || 0})</summary>
                    <ul className="mt-1 bg-slate-950 border border-slate-800 rounded p-2 space-y-1 max-w-md">
                      {(m.facts || []).map((f, j) => (
                        <li key={j} className="text-[10px] text-slate-400 font-mono">{f}</li>
                      ))}
                    </ul>
                  </details>
                </div>
              </div>
            )
          )}

          {busy && (
            <div className="self-start max-w-[85%] bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-[12px] text-slate-400">
              <span className="animate-pulse">Thinking…</span>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        <div className="border-t border-slate-800 p-3 flex gap-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKey}
            rows={2}
            disabled={!jobId || busy}
            placeholder={jobId ? 'Ask about this dataset…' : 'Select a dataset first'}
            aria-label="Ask a question about this dataset"
            className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-emerald-600 resize-none disabled:opacity-50"
          />
          <button
            onClick={() => send()}
            disabled={!jobId || busy || !input.trim()}
            className="btn px-4 py-2 text-xs self-end disabled:opacity-40"
          >
            SEND
          </button>
        </div>
      </div>

      {error && <div className="mt-3 text-sm text-red-400" role="alert">{error}</div>}
    </div>
  )
}