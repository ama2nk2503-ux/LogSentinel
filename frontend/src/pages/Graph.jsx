import { useCallback, useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import PageHeader from '../components/PageHeader.jsx'
import { api } from '../lib/api.js'

const SEV_COLOR = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' }

export default function Graph() {
  const [jobId, setJobId] = useState('')
  const [selected, setSelected] = useState(null)
  const [cyReady, setCyReady] = useState(false)
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const cyModRef = useRef(null)

  useEffect(() => {
    let cancelled = false
    import('cytoscape').then((m) => {
      cyModRef.current = m.default
      if (!cancelled) setCyReady(true)
    })
    return () => { cancelled = true }
  }, [])

  const { data: graph, error, isLoading } = useQuery({
    queryKey: ['graph', jobId],
    queryFn: () => api(`/graph/${jobId}`),
    enabled: !!jobId,
  })

  // (re)render graph when data or selection changes
  useEffect(() => {
    if (!graph || !containerRef.current || !cyModRef.current) return
    if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null }

    const elements = []
    for (const n of graph.nodes) {
      elements.push({
        data: {
          id: n.id, label: n.label,
          color: n.flagged ? SEV_COLOR.HIGH : n.type === 'user' ? '#a855f7' : '#3b82f6',
          size: 14 + Math.min(26, n.risk / 3),
          shape: n.type === 'user' ? 'star' : n.type === 'host' ? 'round-rectangle' : 'ellipse',
        },
      })
    }
    for (const e of graph.edges) {
      elements.push({
        data: {
          source: e.source, target: e.target,
          width: 1 + Math.min(5, Math.log2(1 + e.weight)),
          color: e.severity === 'HIGH' || e.severity === 'CRITICAL' ? '#ef4444'
            : e.severity === 'MEDIUM' ? '#eab308' : '#334155',
        },
      })
    }

    const cy = cyModRef.current({
      container: containerRef.current,
      elements,
      style: [
        { selector: 'node', style: {
            'background-color': 'data(color)', label: 'data(label)',
            width: 'data(size)', height: 'data(size)', shape: 'data(shape)',
            color: '#cbd5e1', 'font-size': 8, 'text-valign': 'bottom', 'text-margin-y': 4,
        } },
        { selector: 'node[?flagged]', style: {
            'border-width': 3, 'border-color': '#ef4444',
        } },
        { selector: 'edge', style: {
            width: 'data(width)', 'line-color': 'data(color)',
            'curve-style': 'bezier', opacity: 0.7,
        } },
      ],
      layout: { name: 'cose', animate: true, padding: 30,
                idealEdgeLength: () => 80 },
      wheelSensitivity: 0.2,
    })

    cy.on('tap', 'node', (evt) => setSelected(evt.target.data('id')))
    cy.on('tap', (e) => { if (e.target === cy) setSelected(null) })
    cyRef.current = cy
    // Size cytoscape to the now-visible container (614px tall with proper absolute positioning)
    if (cy) { cy.fit(); cy.on('resize', () => {}) }
    return () => { if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null } }
  }, [graph, cyReady])

  const node = selected && graph ? graph.nodes.find((n) => n.id === selected) : null

  return (
    <div className="p-4 md:p-6 lg:p-8 h-full flex flex-col">
      <PageHeader title="LIVE ATTACK GRAPH" />
      <div className="flex gap-3 items-center mb-4">
        <JobPicker value={jobId} onChange={setJobId} />
        {graph && (
          <span className="text-[11px] text-slate-500">
            {graph.nodes.length} nodes · {graph.edges.length} links ·{' '}
            <span className="text-red-400">red ring = flagged entity</span>
          </span>
        )}
      </div>

      {!jobId && <div className="text-sm text-slate-500">Select a processed dataset to visualize attacker interactions.</div>}
      {error && <div className="text-sm text-red-400 mb-2">{error.message}</div>}

      {jobId && isLoading && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-sm text-slate-400">Loading graph...</div>
        </div>
      )}

      {jobId && graph && graph.nodes.length === 0 && (
        <div className="text-sm text-slate-500 border border-slate-800 rounded p-4 bg-slate-900/40">
          No entities found for this dataset yet — process some logs first.
        </div>
      )}

      {graph && graph.nodes.length > 0 && (
        <div className="relative flex-1 min-h-[440px]">
          {/* full-width canvas — the entity card floats on top, never squeezing it */}
          <div
            ref={containerRef}
            role="img"
            aria-label={`Attack graph with ${graph.nodes.length} nodes and ${graph.edges.length} links`}
            style={{
              position: 'absolute',
              inset: 0,
              border: '1px solid #374151',
              borderRadius: '0.5rem',
              background: 'rgba(31,41,55,0.8)',
            }}
          />

          {node && (
            <aside className="absolute top-3 right-3 z-10 w-80 max-w-[85%] max-h-[calc(100%-1.5rem)] overflow-auto border border-emerald-800/60 rounded-lg bg-bg-surface/95 shadow-xl shadow-black/50 backdrop-blur p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs tracking-widest text-emerald-400">ENTITY</span>
                <button onClick={() => setSelected(null)}
                        className="w-6 h-6 grid place-items-center text-slate-400 hover:text-white hover:bg-slate-700/60 rounded">
                  ✕
                </button>
              </div>
              <div className="font-bold text-sm mb-2 break-all">{node.label}</div>
              <div className="text-[11px] text-slate-400 space-y-1 mb-3">
                <div>type: <b>{node.type}</b></div>
                <div>risk score: <b style={{ color: node.risk >= 51 ? '#ef4444' : '#94a3b8' }}>{node.risk}</b></div>
                {node.rules.length > 0 && (
                  <div>matched rules:
                    <ul className="mt-1 space-y-0.5">
                      {node.rules.map((r) => <li key={r} className="text-purple-300">{r}</li>)}
                    </ul>
                  </div>
                )}
              </div>
              <EntityEvidence jobId={jobId} entity={node.id} />
            </aside>
          )}
        </div>
      )}
    </div>
  )
}

function EntityEvidence({ jobId, entity }) {
  const [rows, setRows] = useState([])
  useEffect(() => {
    let stop = false
    api(`/events?job_id=${jobId}&q=${encodeURIComponent(entity)}&page_size=12`)
      .then((d) => { if (!stop) setRows(d.events || []) }).catch(() => {})
    return () => { stop = true }
  }, [jobId, entity])

  return (
    <div>
      <div className="text-[10px] tracking-widest text-slate-500 mb-1">EVIDENCE EVENTS</div>
      <div className="space-y-1 max-h-64 overflow-auto">
        {rows.map((e) => (
          <div key={e.id} className="text-[10px] border-l-2 border-slate-700 pl-2">
            <span className="text-slate-500">{(e.ts || '').slice(11, 19)}</span>{' '}
            <span className={e.threat_type ? 'text-red-300' : 'text-slate-300'}>
              {(e.message || '').slice(0, 90)}
            </span>
          </div>
        ))}
        {rows.length === 0 && <div className="text-[10px] text-slate-600">no events found</div>}
      </div>
    </div>
  )
}
