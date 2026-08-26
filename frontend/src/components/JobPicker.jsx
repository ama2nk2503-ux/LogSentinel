import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api.js'

export default function JobPicker({ value, onChange }) {
  const { data } = useQuery({
    queryKey: ['jobs'],
    queryFn: () => api('/jobs').then((d) => d.jobs),
  })

  return (
    <select
      value={value || ''}
      onChange={(e) => onChange(e.target.value)}
      className="bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-emerald-600"
    >
      <option value="">— select dataset —</option>
      {(data || []).map((j) => (
        <option key={j.id} value={j.id}>
          {j.filename} · {j.detected_format || j.status}
        </option>
      ))}
    </select>
  )
}
