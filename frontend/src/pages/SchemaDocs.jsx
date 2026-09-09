import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import JobPicker from '../components/JobPicker.jsx'
import PageHeader from '../components/PageHeader.jsx'
import Skeleton from '../components/Skeleton.jsx'
import { api } from '../lib/api.js'
import useQueryParam from '../lib/useQueryParam.js'

const TYPE_COLORS = {
  'str': 'text-sky-300',
  'int': 'text-amber-300',
  'float': 'text-amber-300',
  'bool': 'text-purple-300',
  'array<str>': 'text-green-300',
  'array<int>': 'text-green-300',
  'object': 'text-orange-300',
  'unknown': 'text-slate-400',
}

export default function SchemaDocs() {
  const [jobId, setJobId] = useQueryParam('job', '')

  const { data, isLoading, error } = useQuery({
    queryKey: ['schema-docs', jobId],
    queryFn: () => api(`/schema/docs/${jobId}`),
    enabled: !!jobId,
  })

  return (
    <div className="p-4 md:p-6 lg:p-8">
      <PageHeader title="UNIVERSAL EVENT SCHEMA DOCS" subtitle="Field mappings to ECS & OCSF with coverage" />

      <div className="flex flex-wrap gap-3 items-center mb-4">
        <JobPicker value={jobId} onChange={setJobId} />
        {!jobId && <span className="text-sm text-slate-500">Select a processed dataset to view schema coverage</span>}
      </div>

      {!jobId && (
        <div className="text-center py-12 text-slate-500">
          <div className="text-4xl mb-4">📋</div>
          <p className="text-lg">Choose a job from the dropdown to see field coverage statistics</p>
          <p className="text-sm mt-2">Coverage % shows how often each field is populated in the current dataset</p>
        </div>
      )}

      {jobId && isLoading && <Skeleton rows={12} className="mt-4" />}

      {jobId && error && (
        <div className="mt-4 p-4 bg-red-900/20 border border-red-800 rounded text-red-300 text-sm">
          Failed to load schema docs: {error.message || 'Unknown error'}
        </div>
      )}

      {jobId && data && !isLoading && (
        <>
          <div className="mb-4 flex flex-wrap gap-4 text-sm text-slate-400">
            <span>Total events: <span className="text-white font-mono">{data.total_events}</span></span>
            <span>Fields documented: <span className="text-white font-mono">{data.fields.length}</span></span>
          </div>

          <div className="border border-slate-800 rounded overflow-hidden">
            <table className="w-full text-xs min-w-[1000px]" aria-label="Universal Event Schema Field Mappings">
              <thead className="bg-slate-900/80 text-slate-500 tracking-wider">
                <tr>
                  <th className="px-3 py-2 text-left font-normal whitespace-nowrap">FIELD</th>
                  <th className="px-3 py-2 text-left font-normal whitespace-nowrap">TYPE</th>
                  <th className="px-3 py-2 text-left font-normal whitespace-nowrap">ECS FIELD</th>
                  <th className="px-3 py-2 text-left font-normal whitespace-nowrap">OCSF FIELD</th>
                  <th className="px-3 py-2 text-left font-normal whitespace-nowrap">COVERAGE</th>
                  <th className="px-3 py-2 text-left font-normal">DESCRIPTION</th>
                </tr>
              </thead>
              <tbody>
                {data.fields.map((f) => (
                  <tr key={f.field} className="border-t border-slate-800/60 hover:bg-slate-800/30">
                    <td className="px-3 py-2 text-emerald-300 font-mono whitespace-nowrap">{f.field}</td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <span className={TYPE_COLORS[f.type] || 'text-slate-400'}>{f.type}</span>
                    </td>
                    <td className="px-3 py-2 text-sky-300 font-mono whitespace-nowrap">{f.ecs}</td>
                    <td className="px-3 py-2 text-purple-300 font-mono whitespace-nowrap">{f.ocsf}</td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 max-w-32 h-2 bg-slate-800 rounded overflow-hidden">
                          <div
                            className="h-full bg-emerald-500"
                            style={{ width: `${f.coverage}%` }}
                          />
                        </div>
                        <span className="text-white font-mono w-12 text-right">{f.coverage}%</span>
                      </div>
                    </td>
                    <td className="px-3 py-2 text-slate-300 max-w-xs truncate" title={f.description}>{f.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-4 p-3 bg-slate-900/40 border border-slate-800 rounded text-xs text-slate-500">
            <strong className="text-slate-400">Legend:</strong> Coverage = % of events in this job where the field is non-empty.
            ECS = Elastic Common Schema 1.16+ field names. OCSF = Open Cybersecurity Schema Framework 1.3.0
            (Auth 3002 / Network Activity 4001 / Application Lifecycle 1008 class mappings).
          </div>
        </>
      )}
    </div>
  )
}