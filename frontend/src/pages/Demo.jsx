import { useCallback, useEffect, useRef, useState } from 'react'
import { api, apiText } from '../lib/api.js'
import PageHeader from '../components/PageHeader.jsx'

const SCENARIOS = [
    { file: 'scenario1_ssh_bruteforce.log', label: 'SSH Brute Force → Account Compromise' },
    { file: 'scenario2_port_scan.log', label: 'Network Port Scan' },
    { file: 'scenario3_web_attack.log', label: 'Web Application Attack' },
    { file: 'scenario4_windows_auth.xml', label: 'Windows Logon Attack + PowerShell' },
]

const STAGE_STEPS = [
    ['uploaded', 'Ingesting raw log…'],
    ['detected', 'Detecting format & confidence…'],
    ['parsed', 'Parsing heterogeneous lines…'],
    ['normalized', 'Normalizing to universal schema…'],
    ['ioc_extracted', 'Extracting IOCs & suspicious patterns…'],
    ['classified', 'Correlating · classifying · scoring risk…'],
]

export default function Demo() {
    const [running, setRunning] = useState(false)
    const [step, setStep] = useState(0)          // scenario index
    const [stage, setStage] = useState('')
    const [narration, setNarration] = useState([])
    const [done, setDone] = useState(null)       // summary when finished
    const [error, setError] = useState('')
    const cancelled = useRef(false)

    const narr = useCallback((line) => {
        setNarration((n) => [...n, line])
    }, [])

    const run = useCallback(async () => {
        setRunning(true); setError(''); setDone(null)
        setNarration([]); setStep(0); cancelled.current = false
        const totals = { events: 0, iocs: 0, threats: 0, pii: 0, formats: [] }

        try {
            for (let s = 0; s < SCENARIOS.length; s++) {
                if (cancelled.current) return
                setStep(s)
                const sc = SCENARIOS[s]
                narr(`▶ Scenario ${s + 1}: ${sc.label}`)

                // 1. load sample content
                setStage('uploading')
                narr('  Uploading dataset…')
                const text = await apiText(`/samples/${encodeURIComponent(sc.file)}`)
                const up = await api('/paste', { method: 'POST', body: JSON.stringify({ text, name: sc.file }) })
                const jobId = up.job_id

                // 2. poll real pipeline milestones
                let job
                for (;;) {
                    if (cancelled.current) return
                    await new Promise((r) => setTimeout(r, 350))
                    job = await api(`/jobs/${jobId}`)
                    setStage(job.stage)
                    if (job.status === 'done' || job.status === 'error') break
                }
                if (job.status === 'error') throw new Error(job.error)

                // 3. narrate with ACTUAL numbers from this run
                const st = job.stats || {}
                narr(`  ✓ Format detected: ${job.detected_format} (${job.format_confidence}% confidence)`)
                narr(`  ✓ Parsed ${st.total_lines} lines → normalized events`)
                if ((st.total_iocs ?? 0) > 0) narr(`  ✓ Extracted ${st.total_iocs} IOC${st.total_iocs === 1 ? '' : 's'}`)
                totals.events += st.total_lines || 0
                totals.iocs += st.total_iocs || 0
                totals.pii += st.pii_events || 0
                totals.formats.push(job.detected_format)

                const dash = await api(`/dashboard/${jobId}`)
                narr(`  ✓ Correlated into ${dash.cards.threats} threat incident(s), ${dash.cards.critical} critical`)
                totals.threats += dash.cards.threats

                const threats = await api(`/threats/${jobId}`)
                for (const inc of threats.incidents.slice(0, 2)) {
                    narr(`  ⚠ ${inc.title} — risk ${inc.risk_score} (${inc.classification})`)
                }
            }
            narr('')
            narr('★ DEMO COMPLETE — all scenarios processed through the full pipeline')
            setDone(totals)
        } catch (e) {
            setError(String(e.message || e))
        } finally {
            setRunning(false); setStage('')
        }
    }, [narr])

    const stop = () => { cancelled.current = true; setRunning(false) }

    useEffect(() => () => { cancelled.current = true }, [])

    return (
        <div className="p-4 md:p-6 lg:p-8">
            <PageHeader title="CINEMATIC DEMO MODE" subtitle="Runs the four attack scenarios end-to-end through the real pipeline — every number shown is computed live." />

            {!running && !done && (
                <button onClick={run}
                        className="btn btn-primary px-8 py-3 relative overflow-hidden">
                    ▶ START FULL PIPELINE DEMO
                </button>
            )}
            {running && (
                <button onClick={stop}
                        className="btn btn-danger px-6 py-2 text-xs">
                    ■ STOP
                </button>
            )}

            {running && (
                <div className="mt-6 border border-emerald-800 rounded-lg bg-black/60 p-5 font-mono text-[12px] leading-6 max-w-2xl">
                    <div className="flex gap-1.5 mb-3" role="progressbar" aria-valuemin={0} aria-valuemax={SCENARIOS.length} aria-valuenow={Math.min(step + 1, SCENARIOS.length)} aria-label="Demo pipeline progress">
                        {SCENARIOS.map((_, i) => (
                            <span key={i} className={`h-1.5 flex-1 rounded-full ${i < step ? 'bg-emerald-500' : i === step ? 'bg-emerald-400 animate-pulse' : 'bg-slate-700'}`} />
                        ))}
                    </div>
                    <div className="text-slate-500 mb-1">STAGE: <span className="text-emerald-400">{stage}</span></div>
                    {narration.slice(-14).map((l, i) => (
                        <div key={i} className={l.startsWith('⚠') ? 'text-orange-300' : l.startsWith('★') ? 'text-emerald-400 font-bold' : l.startsWith('▶') ? 'text-sky-300 font-bold mt-2' : 'text-slate-300'} aria-live="polite">
                            {l}
                        </div>
                    ))}
                </div>
            )}

            {done && (
                <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-3 max-w-2xl">
                    {[['TOTAL EVENTS', done.events], ['IOCS EXTRACTED', done.iocs],
                      ['THREAT INCIDENTS', done.threats], ['PII EVENTS', done.pii]].map(([k, v]) => (
                        <div key={k} className="border border-slate-800 bg-slate-900/60 rounded p-4 text-center">
                            <div className="text-2xl font-bold text-emerald-400">{v}</div>
                            <div className="text-[10px] tracking-widest text-slate-500 mt-1">{k}</div>
                        </div>
                    ))}
                </div>
            )}

            {error && <div className="mt-4 text-sm text-red-400" role="alert">{error}</div>}
</div>
  )
}
