import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function PublicOnlyRoute({ children }) {
  const { user, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex min-h-[calc(100vh-73px)] items-center justify-center text-smoke">
        Loading…
      </div>
    )
  }
  if (user) {
    return <Navigate to="/dashboard" replace />
  }
  return children
}
