import { lazy, Suspense } from 'react'
import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout.jsx'
import ProtectedRoute from './components/ProtectedRoute.jsx'
import Login from './pages/Login.jsx'

const Upload = lazy(() => import('./pages/Upload.jsx'))
const Dashboard = lazy(() => import('./pages/Dashboard.jsx'))
const Explorer = lazy(() => import('./pages/Explorer.jsx'))
const Alerts = lazy(() => import('./pages/Alerts.jsx'))
const Live = lazy(() => import('./pages/Live.jsx'))
const Threats = lazy(() => import('./pages/Threats.jsx'))
const Graph = lazy(() => import('./pages/Graph.jsx'))
const Intel = lazy(() => import('./pages/Intel.jsx'))
const Compliance = lazy(() => import('./pages/Compliance.jsx'))
const Assets = lazy(() => import('./pages/Assets.jsx'))
const Privacy = lazy(() => import('./pages/Privacy.jsx'))
const ExportPage = lazy(() => import('./pages/ExportPage.jsx'))
const Benchmark = lazy(() => import('./pages/Benchmark.jsx'))
const Demo = lazy(() => import('./pages/Demo.jsx'))
const SchemaDocs = lazy(() => import('./pages/SchemaDocs.jsx'))
const ParserLab = lazy(() => import('./pages/ParserLab.jsx'))
const Assistant = lazy(() => import('./pages/Assistant.jsx'))
const Modes = lazy(() => import('./pages/Modes.jsx'))

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-sm text-slate-400">Loading...</div>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route path="/" element={<Suspense fallback={<PageLoader />}><Upload /></Suspense>} />
          <Route path="/demo" element={<Suspense fallback={<PageLoader />}><Demo /></Suspense>} />
          <Route path="/dashboard" element={<Suspense fallback={<PageLoader />}><Dashboard /></Suspense>} />
          <Route path="/dashboard/:jobId" element={<Suspense fallback={<PageLoader />}><Dashboard /></Suspense>} />
          <Route path="/explorer" element={<Suspense fallback={<PageLoader />}><Explorer /></Suspense>} />
          <Route path="/threats" element={<Suspense fallback={<PageLoader />}><Threats /></Suspense>} />
          <Route path="/alerts" element={<Suspense fallback={<PageLoader />}><Alerts /></Suspense>} />
          <Route path="/live" element={<Suspense fallback={<PageLoader />}><Live /></Suspense>} />
          <Route path="/graph" element={<Suspense fallback={<PageLoader />}><Graph /></Suspense>} />
          <Route path="/intel" element={<Suspense fallback={<PageLoader />}><Intel /></Suspense>} />
          <Route path="/compliance" element={<Suspense fallback={<PageLoader />}><Compliance /></Suspense>} />
          <Route path="/assets" element={<Suspense fallback={<PageLoader />}><Assets /></Suspense>} />
          <Route path="/privacy" element={<Suspense fallback={<PageLoader />}><Privacy /></Suspense>} />
          <Route path="/export" element={<Suspense fallback={<PageLoader />}><ExportPage /></Suspense>} />
          <Route path="/benchmark" element={<Suspense fallback={<PageLoader />}><Benchmark /></Suspense>} />
          <Route path="/schema-docs" element={<Suspense fallback={<PageLoader />}><SchemaDocs /></Suspense>} />
          <Route path="/parser-lab" element={<Suspense fallback={<PageLoader />}><ParserLab /></Suspense>} />
          <Route path="/assistant" element={<Suspense fallback={<PageLoader />}><Assistant /></Suspense>} />
          <Route path="/modes" element={<Suspense fallback={<PageLoader />}><Modes /></Suspense>} />
        </Route>
      </Route>
    </Routes>
  )
}
