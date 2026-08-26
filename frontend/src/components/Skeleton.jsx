import { memo } from 'react'

const Skeleton = memo(function Skeleton({ rows = 5, className = '' }) {
  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-8 bg-slate-800/50 rounded animate-pulse" />
      ))}
    </div>
  )
})

export default Skeleton
