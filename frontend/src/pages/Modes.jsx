import PageHeader from '../components/PageHeader.jsx'

const MODES = [
  {
    icon: '🎬',
    name: 'DEMO',
    title: 'Demo (bundled samples)',
    tone: 'border-fuchsia-800 bg-fuchsia-950/20',
    points: [
      'One-click attack scenarios (brute force, port scan, web attacks, Windows auth)',
      'Feeds the bundled sample files through the real 17-stage pipeline',
      'Detections shown are computed live by the actual rules — nothing is scripted',
      'Cinematic narration explains each stage as it completes',
    ],
  },
  {
    icon: '🏭',
    name: 'PRODUCTION',
    title: 'Production (offline, air-gapped)',
    tone: 'border-emerald-800 bg-emerald-950/20',
    points: [
      'Zero network calls at runtime — every dependency is local and bundled',
      'SQLite WAL storage, JWT auth, bcrypt hashes; binds 127.0.0.1 only',
      'Offline GeoIP (~30k subnet buckets) and seeded threat-intel reference feed',
      'IsolationForest anomaly model trains per job on-device; no model downloads',
    ],
  },
  {
    icon: '📤',
    name: 'CUSTOM UPLOAD',
    title: 'Custom upload',
    tone: 'border-sky-800 bg-sky-950/20',
    points: [
      'Drag & drop a file, paste raw text, or pick a bundled sample',
      'Extension whitelist (.log .txt .json .csv .xml) + size cap enforced server-side',
      'Files stored under UUID names; content is parsed, never executed',
      'Everything flows through the single privacy-policy choke point on the way out',
    ],
  },
]

const GUARANTEES = [
  ['No telemetry', 'no analytics, phoning-home, or crash reporting — ever'],
  ['No cloud APIs', 'no outbound requests to any third-party service'],
  ['No required API keys', 'every feature works with an empty .env'],
  ['Optional local LLM assistance', 'auto-on the moment a tiny local model is present; only dials a localhost endpoint you run, and the app is identical with it absent'],
]

export default function Modes() {
  return (
    <div className="p-4 md:p-6 lg:p-8">
      <PageHeader
        title="MODES"
        subtitle="Three ways to run — one offline guarantee you can verify"
      />

      <div className="grid md:grid-cols-3 gap-4 mb-6">
        {MODES.map((m) => (
          <section key={m.name} className={`border rounded-lg p-4 ${m.tone}`} aria-label={m.title}>
            <div className="text-2xl mb-2" aria-hidden="true">{m.icon}</div>
            <h2 className="text-sm font-bold tracking-widest text-white mb-3">{m.title}</h2>
            <ul className="space-y-2">
              {m.points.map((p) => (
                <li key={p} className="text-xs text-slate-300 flex gap-2">
                  <span aria-hidden="true" className="text-emerald-500">▸</span>
                  <span>{p}</span>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>

      <div className="border border-slate-800 bg-slate-900/60 rounded-lg p-4">
        <h2 className="text-sm font-bold tracking-widest text-white mb-3">THE OFFLINE GUARANTEE</h2>
        <p className="text-xs text-slate-400 mb-4">
          LogSentinel makes zero network calls at runtime. This is an inspectable property of the
          codebase, not a README promise: every network-touching module is local-only, and the only
          optional outbound feature (AI narration) engages automatically when you run a small local
          LLM yourself — until then it stays fully deterministic.
        </p>
        <div className="grid sm:grid-cols-2 gap-3">
          {GUARANTEES.map(([t, d]) => (
            <div key={t} className="border border-slate-800 rounded p-3 bg-slate-950/40">
              <div className="text-xs font-bold text-emerald-400 mb-1">✓ {t}</div>
              <div className="text-[11px] text-slate-400">{d}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
