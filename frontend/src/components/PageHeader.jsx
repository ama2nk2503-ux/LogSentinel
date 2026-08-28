export default function PageHeader({ title, subtitle }) {
  return (
    <>
      <h1 className={`text-lg tracking-[0.25em] text-emerald-400 ${subtitle ? 'mb-1' : 'mb-5'}`}>{title}</h1>
      {subtitle && <p className="text-xs text-slate-500 mb-6">{subtitle}</p>}
    </>
  )
}