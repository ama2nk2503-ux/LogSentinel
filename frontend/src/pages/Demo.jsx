import { useCallback, useEffect, useRef, useState } from 'react'
import { api, apiText } from '../lib/api.js'
import PageHeader from '../components/PageHeader.jsx'
import Aurora from '../components/bits/Aurora.jsx'
import StarBorder from '../components/bits/StarBorder.jsx'
import SplitFlapText from '../components/bits/SplitFlapText.jsx'
import CountUp from '../components/bits/CountUp.jsx'

const LEGACY_SCENARIOS = [
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
    const [scenarios, setScenarios] = useState(LEGACY_SCENARIOS)
    const [aiStatus, setAiStatus] = useState(null)
    const cancelled = useRef(false)

    useEffect(() => {
        api('/assistant/status')
            .then(setAiStatus)
            .catch(() => {})
    }, [])

    useEffect(() => {
        api('/samples')
            .then((r) => {
                const list = r?.samples || []
                if (list.length >= 4) {
                    setScenarios(list
                        .filter((s) => s.file)
                        .sort((a, b) => (a.scenario ?? 99) - (b.scenario ?? 99))
                        .map((s) => ({ file: s.file, label: s.title || s.name, description: s.description || '', severity: s.severity_hint || '', events: s.sample_events, format: s.format, iocs: s.iocs || [] })))
                }
            })
            .catch(() => {})
    }, [])

    const narr = useCallback((line) => {
        setNarration((n) => [...n, line])
    }, [])

    const run = useCallback(async () => {
        setRunning(true); setError(''); setDone(null)
        setNarration([]); setStep(0); cancelled.current = false
        const totals = { events: 0, iocs: 0, threats: 0, pii: 0, formats: [],
                         severity: {}, classification: {}, aiSources: [] }

        try {
            for (let s = 0; s < scenarios.length; s++) {
                if (cancelled.current) return
                setStep(s)
                const sc = scenarios[s]
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
                const incs = threats.incidents || []
                for (const inc of incs.slice(0, 2)) {
                    narr(`  ⚠ ${inc.title} — ${inc.severity} · risk ${inc.risk_score} (${inc.classification})`)
                    if (inc.ai_summary?.narration) {
                        narr(`    ✦ AI: ${inc.ai_summary.narration}`)
                        narr(`    ⚠ ${inc.ai_summary.disclaimer}`)
                        totals.aiSources.push(inc.ai_summary.source || 'deterministic_template')
                    }
                }
                for (const inc of incs) {
                    const sev = (inc.severity || 'Unknown').toUpperCase()
                    const cls = (inc.classification || 'Unknown').toUpperCase()
                    totals.severity[sev] = (totals.severity[sev] || 0) + 1
                    totals.classification[cls] = (totals.classification[cls] || 0) + 1
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
        <div className="relative min-h-full">
            <div className="absolute inset-0" aria-hidden="true">
                <Aurora speed={0.8} amplitude={1.1} />
            </div>
            <div className="absolute inset-0 bg-bg-sunken/60" aria-hidden="true" />
            <div className="relative p-4 md:p-6 lg:p-8">
                <PageHeader title="CINEMATIC DEMO MODE" subtitle={`Runs all ${scenarios.length} attack scenarios end-to-end through the real pipeline — every number shown is computed live.`} />

                <div className="mb-6 max-w-2xl">
                    <div className="label mb-2">SCENARIOS QUEUED</div>
                    <div className="scroll-list no-scrollbar">
                        {scenarios.map((s) => {
                            const sev = (s.severity || '').toUpperCase()
                            const sevCls = sev === 'CRITICAL' ? 'text-red-400 border-red-800/70 bg-red-500/10'
                                : sev === 'HIGH' ? 'text-orange-300 border-orange-800/70 bg-orange-500/10'
                                : sev === 'MEDIUM' ? 'text-amber-300 border-amber-800/70 bg-amber-500/10'
                                : 'text-sky-300 border-sky-800/70 bg-sky-500/10'
                            return (
                                <div key={s.file} className="item">
                                    <div className="flex justify-between items-start gap-2">
                                        <p className="item-text">{s.label}</p>
                                        {sev && <span className={`shrink-0 px-1.5 py-0.5 rounded border text-[9px] font-mono tracking-wider ${sevCls}`}>{sev}</span>}
                                    </div>
                                    {s.description && <p className="text-[10px] text-slate-500 mt-0.5">{s.description}</p>}
                                    <p className="text-[9px] text-slate-600 font-mono mt-0.5">{`${s.events ?? '–'} events · ${s.format ?? '–'}`}{(s.iocs && s.iocs.length) ? ` · ${s.iocs.length} IOC` : ''}</p>
                                </div>
                            )
                        })}
                    </div>
                </div>

                {!running && !done && (
                    <StarBorder speed="4s" onClick={run}>
                        <span className="text-sm tracking-widest font-bold text-emerald-300">▶ START FULL PIPELINE DEMO</span>
                    </StarBorder>
                )}
                {running && (
                    <button onClick={stop}
                            className="btn btn-danger px-6 py-2 text-xs">
                        ■ STOP
                    </button>
                )}

                {running && (
                    <div className="mt-6 border border-emerald-800 rounded-lg bg-black/60 p-5 font-mono text-[12px] leading-6 max-w-2xl shadow-[0_0_24px_rgba(16,185,129,0.12)]">
                        <div className="flex gap-1.5 mb-3" role="progressbar" aria-valuemin={0} aria-valuemax={scenarios.length} aria-valuenow={Math.min(step + 1, scenarios.length)} aria-label="Demo pipeline progress">
                            {scenarios.map((_, i) => (
                                <span key={i} className={`h-1.5 flex-1 rounded-full ${i < step ? 'bg-emerald-500' : i === step ? 'bg-emerald-400 animate-pulse' : 'bg-slate-700'}`} />
                            ))}
                        </div>
                        <div className="flex items-center gap-3 mb-2">
                            <span className="text-slate-500">STAGE:</span>
                            <span aria-live="polite">
                                <SplitFlapText text={stage} fontSize={16} gap={4} tileRadius={5} padTo={10} flipDuration={0.09} stagger={0.03} loop={false} />
                            </span>
                        </div>
                        {narration.slice(-14).map((l, i) => (
                            <div key={i} className={l.startsWith('⚠') ? 'text-orange-300' : l.startsWith('★') ? 'text-emerald-400 font-bold' : l.startsWith('▶') ? 'text-sky-300 font-bold mt-2' : 'text-slate-300'} aria-live="polite">
                                {l}
                            </div>
                        ))}
                    </div>
                )}

                {done && (
                    <>
                    <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-3 max-w-2xl">
                        {[['TOTAL EVENTS', done.events], ['IOCS EXTRACTED', done.iocs],
                          ['THREAT INCIDENTS', done.threats], ['PII EVENTS', done.pii]].map(([k, v]) => (
                            <div key={k} className="border border-emerald-900/70 bg-slate-900/60 rounded p-4 text-center shadow-[0_0_16px_rgba(16,185,129,0.10)]">
                                <div className="text-2xl font-bold text-emerald-400 font-mono">
                                    <CountUp to={v} duration={1.2} />
                                </div>
                                <div className="text-[10px] tracking-widest text-slate-500 mt-1">{k}</div>
                            </div>
                        ))}
                    </div>

                    {(Object.keys(done.severity).length > 0 || Object.keys(done.classification).length > 0) && (
                        <div className="mt-6 max-w-2xl grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="border border-emerald-900/70 bg-slate-900/60 rounded p-4">
                                <div className="label mb-2">SEVERITY BREAKDOWN</div>
                                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
                                    <div key={lvl} className="flex justify-between items-center py-1 text-[12px] font-mono">
                                        <span className={`${lvl === 'CRITICAL' ? 'text-red-400' : lvl === 'HIGH' ? 'text-orange-300' : lvl === 'MEDIUM' ? 'text-amber-300' : 'text-sky-300'}`}>{lvl}</span>
                                        <span className="text-emerald-300">{done.severity[lvl] || 0}</span>
                                    </div>
                                ))}
                            </div>
                            <div className="border border-emerald-900/70 bg-slate-900/60 rounded p-4">
                                <div className="label mb-2">CLASSIFICATION BREAKDOWN</div>
                                {['MALICIOUS', 'SUSPICIOUS', 'BENIGN'].map((cls) => (
                                    <div key={cls} className="flex justify-between items-center py-1 text-[12px] font-mono">
                                        <span className={cls === 'MALICIOUS' ? 'text-red-300' : cls === 'SUSPICIOUS' ? 'text-amber-300' : 'text-sky-300'}>{cls}</span>
                                        <span className="text-emerald-300">{done.classification[cls] || 0}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    <div className="mt-6 max-w-2xl">
                        <div className="label mb-2">AI NARRATION</div>
                        <div className="flex flex-wrap items-center gap-3 border border-purple-900/70 bg-slate-900/60 rounded p-4">
                            {aiStatus?.mode === 'off'
                                ? <><span className="text-[12px] font-mono text-slate-400">○ AI OFF — deterministic evidence only</span></>
                                : aiStatus?.llm_available
                                    ? <><span className="text-[12px] font-mono text-purple-300">● AI ON — {aiStatus.model || 'local'}</span></>
                                    : aiStatus?.mode === 'on'
                                        ? <><span className="text-[12px] font-mono text-amber-300">● AI ENABLED — deterministic template (local LLM unreachable)</span></>
                                        : <><span className="text-[12px] font-mono text-slate-400">● AUTO — deterministic template (no local model detected)</span></>}
                            {done.aiSources.length > 0 && (
                                <span className="text-[10px] text-slate-500">{done.aiSources.length} incident narration(s) shown this run</span>
                            )}
                        </div>
                    </div>
                    </>
                )}

                {error && <div className="mt-4 text-sm text-red-400" role="alert">{error}</div>}
            </div>
        </div>
    )
}