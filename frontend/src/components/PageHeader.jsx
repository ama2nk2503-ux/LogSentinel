import { motion } from 'motion/react'
import CountUp from './bits/CountUp.jsx'

export default function PageHeader({ title, subtitle, count, countLabel }) {
  return (
    <motion.div
      initial={{ y: 8 }}
      animate={{ y: 0 }}
      transition={{ duration: 0.4, ease: 'easeOut' }}
      className="mb-6"
    >
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <h1 className="text-lg tracking-[0.25em] text-emerald-400 font-mono">{title}</h1>
        {count != null && (
          <div className="flex items-baseline gap-2 mb-1">
            <CountUp to={count} duration={1.2} className="text-2xl font-bold text-emerald-400 font-mono glow-text" />
            {countLabel && <span className="label">{countLabel}</span>}
          </div>
        )}
      </div>
      {subtitle && <p className="text-xs text-slate-500 mt-1">{subtitle}</p>}
    </motion.div>
  )
}