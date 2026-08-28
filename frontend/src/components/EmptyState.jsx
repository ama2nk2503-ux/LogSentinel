export default function EmptyState({ children }) {
  return (
    <div className="border border-slate-800 rounded p-6 text-sm text-slate-500 bg-slate-900/40">
      {children}
    </div>
  )
}