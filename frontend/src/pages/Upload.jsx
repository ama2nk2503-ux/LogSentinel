import { useCallback, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, classNames } from '../lib/api.js'

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
      const res = await fetch('/api/upload', { method: 'POST', body: fd })
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
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
      const text = await fetch(`/api/samples/${encodeURIComponent(name)}`).then((r) => r.text())
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
    <div className="p-4 md:p-6 lg:p-8 max-w-3xl mx-auto">
      <h1 className="text-xl tracking-[0.25em] text-emerald-400 mb-1">UPLOAD CYBER LOGS</h1>
      <p className="text-xs text-slate-500 mb-6">Universal ingestion · format auto-detection · SIEM-ready intelligence</p>

      <div
        className={classNames(
          'border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors',
          dragging ? 'border-emerald-400 bg-emerald-400/10' : 'border-slate-700 hover:border-slate-500 bg-slate-900/40',
        )}
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); uploadFiles(e.dataTransfer.files) }}
        onClick={() => fileInput.current?.click()}
      >
        <div className="text-4xl mb-3">🛡️</div>
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

      {error && <div className="mt-4 text-sm text-red-400 border border-red-800/60 bg-red-950/30 rounded p-3">{error}</div>}

      <div className="mt-6">
        <div className="text-xs tracking-widest text-slate-500 mb-2">OR PASTE RAW LOGS</div>
        <textarea
          value={pasteText}
          onChange={(e) => setPasteText(e.target.value)}
          rows={7}
          placeholder={'Aug 25 10:30:01 server sshd: Failed password for admin from 185.23.45.67'}
          className="w-full bg-slate-950/70 border border-slate-800 rounded p-3 text-xs text-slate-300 focus:outline-none focus:border-emerald-600 font-mono"
        />
        <div className="flex gap-3 mt-3">
          <button
            onClick={uploadPaste}
            disabled={busy || !pasteText.trim()}
            className="px-5 py-2 text-sm tracking-wider bg-emerald-600/90 hover:bg-emerald-500 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded"
          >
            PROCESS PASTED LOGS
          </button>
          <button
            onClick={loadSamples}
            disabled={busy}
            className="px-5 py-2 text-sm tracking-wider border border-slate-700 hover:border-slate-500 text-slate-300 rounded"
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
                className="text-left px-4 py-3 text-xs border border-slate-800 hover:border-emerald-600 hover:bg-emerald-500/5 rounded flex justify-between items-center"
              >
                <span className="text-slate-300">{s.name}</span>
                <span className="text-slate-600">{(s.size / 1024).toFixed(1)} KB</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
