import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { ReactNode } from 'react'

import Dashboard from './pages/Dashboard'
import IncidentDetail from './pages/IncidentDetail'
import Login from './pages/Login'
import ErrorBoundary from './components/ErrorBoundary'
import { useAuthStore } from './store/auth'

function RequireAuth({ children }: { children: ReactNode }) {
  const location = useLocation()
  const isAuthed = useAuthStore((s) => s.isAuthed())
  if (!isAuthed) {
    return <Navigate to="/login" replace state={{ from: location }} />
  }
  return <>{children}</>
}

export default function App() {
  return (
    <BrowserRouter>
      <ErrorBoundary>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <RequireAuth>
                <Dashboard />
              </RequireAuth>
            }
          />
          <Route
            path="/incidents/:id"
            element={
              <RequireAuth>
                <IncidentDetail />
              </RequireAuth>
            }
          />
        </Routes>
      </ErrorBoundary>
    </BrowserRouter>
  )
}
