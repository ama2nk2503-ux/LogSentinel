import { useCallback, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'
import PageHeader from '../components/PageHeader.jsx'
import Aurora from '../components/bits/Aurora.jsx'
import SpotlightCard from '../components/bits/SpotlightCard.jsx'
import { api, apiForm, apiText, classNames } from '../lib/api.js'

const ACCEPT = '.log,.txt,.json,.csv,.xml'

export default function Upload() {
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [pasteText, setPasteText] = useState('')
  const [samples, setSamples] = useState([])
  const [showSamples, setShowSamples] = useState(false)
  const fileInput = useRef(null)
  const navigate = useNavigate()

  const uploadFiles = useCallback(async (fileList) => {
    if (!fileList || fileList.length === 0) return
    setBusy(true); setError('')
    try {
      const fd = new FormData()
      Array.from(fileList).forEach((f) => fd.append('files', f))
      const data = await apiForm('/upload', fd)
      navigate(`/dashboard/${data.jobs[0].job_id}`)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }, [navigate])

  const uploadPaste = useCallback(async () => {
    if (!pasteText.trim()) return
    setBusy(true); setError('')
    try {
      const data = await api('/paste', {
        method: 'POST',
        body: JSON.stringify({ text: pasteText, name: `pasted_${Date.now()}.log` }),
      })
      navigate(`/dashboard/${data.job_id}`)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }, [pasteText, navigate])

  const loadSamples = useCallback(async () => {
    setShowSamples((s) => !s)
    if (samples.length === 0) {
      try { setSamples((await api('/samples')).samples) } catch { /* ignore */ }
    }
  }, [samples])

  const runSample = useCallback(async (name) => {
    setBusy(true); setError('')
    try {
      const text = await apiText(`/samples/${encodeURIComponent(name)}`)
      const data = await api('/paste', {
        method: 'POST',
        body: JSON.stringify({ text, name }),
      })
      navigate(`/dashboard/${data.job_id}`)
    } catch (e) {
      setError(String(e.message || e))
    } finally {
      setBusy(false)
    }
  }, [navigate])

  return (
    <div className="relative min-h-full">
      <div className="absolute inset-0" aria-hidden="true">
        <Aurora speed={0.8} amplitude={1.1} />
      </div>
      <div className="absolute inset-0 bg-bg-sunken/60" aria-hidden="true" />
      <div className="relative p-4 md:p-6 lg:p-8 max-w-3xl mx-auto">
      <PageHeader title="UPLOAD CYBER LOGS" subtitle="Universal ingestion · format auto-detection · SIEM-ready intelligence" />

      <SpotlightCard className="rounded-xl">
        <div
          role="button"
          tabIndex={0}
          aria-label="Upload log files — click or drag and drop log files here"
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.current?.click() } }}
          className={classNames(
            'border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors focus-visible:border-emerald-400',
            dragging ? 'border-emerald-400 bg-emerald-400/10 shadow-[0_0_28px_rgba(16,185,129,0.25)]' : 'border-slate-700 hover:border-slate-500 bg-slate-900/40',
          )}
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); uploadFiles(e.dataTransfer.files) }}
          onClick={() => fileInput.current?.click()}
        >
          <div className="mb-3 flex justify-center" aria-hidden="true">
            <ShieldAlert size={44} strokeWidth={1.5} className="text-emerald-400/80 drop-shadow-[0_0_14px_rgba(52,211,153,0.5)]" />
          </div>
          <div className="text-slate-300 mb-2">{busy ? 'Processing…' : 'Drag & Drop log files here'}</div>
          <div className="text-xs text-slate-500 tracking-widest">LOG · TXT · JSON · CSV · XML</div>
          <input
            ref={fileInput}
            type="file"
            multiple
            accept={ACCEPT}
            className="hidden"
            onChange={(e) => uploadFiles(e.target.files)}
          />
        </div>
      </SpotlightCard>

      {error && <div className="mt-4 alert-error" role="alert">{error}</div>}

      <div className="mt-6">
        <div className="label mb-2">OR PASTE RAW LOGS</div>
        <textarea
          value={pasteText}
          onChange={(e) => setPasteText(e.target.value)}
          rows={7}
          aria-label="Raw log text to paste"
          placeholder={'Aug 25 10:30:01 server sshd: Failed password for admin from 185.23.45.67'}
          className="w-full bg-slate-950/70 border border-slate-800 rounded p-3 text-xs text-slate-300 focus:outline-none focus:border-emerald-600 font-mono"
        />
        <div className="flex gap-3 mt-3">
          <button
            onClick={uploadPaste}
            disabled={busy || !pasteText.trim()}
            className="btn btn-primary px-5 py-2"
          >
            PROCESS PASTED LOGS
          </button>
          <button
            onClick={loadSamples}
            disabled={busy}
            className="btn btn-ghost px-5 py-2"
          >
            {showSamples ? 'HIDE SAMPLES' : 'LOAD SAMPLE SCENARIOS'}
          </button>
        </div>

        {showSamples && (
          <div className="mt-3 grid grid-cols-2 gap-2">
            {samples.map((s) => (
              <button
                key={s.name}
                onClick={() => runSample(s.name)}
                disabled={busy}
                className="text-left px-4 py-3 text-xs border border-slate-800 hover:border-emerald-600 hover:bg-emerald-500/5 rounded flex justify-between items-center disabled:opacity-40"
              >
                <span className="text-slate-300">{s.name}</span>
                <span className="text-slate-600">{(s.size / 1024).toFixed(1)} KB</span>
              </button>
            ))}
          </div>
        )}
      </div>
      </div>
    </div>
  )
}
