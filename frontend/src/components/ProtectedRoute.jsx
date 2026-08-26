import { Navigate, Outlet } from 'react-router-dom'
import { useAuth } from '../lib/AuthContext.jsx'

export default function ProtectedRoute() {
  const { isAuthenticated, loading } = useAuth()
  if (loading) return <div className="min-h-screen grid place-items-center text-slate-500 text-sm">Loading...</div>
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <Outlet />
}
