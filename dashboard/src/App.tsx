import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import IncidentDetail from './pages/IncidentDetail'

// Note: react-router-dom needs to be added to package.json if using routing
// For simplicity, basic routing is shown; add "react-router-dom": "^6.24.0" to deps

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/incidents/:id" element={<IncidentDetail />} />
      </Routes>
    </BrowserRouter>
  )
}
