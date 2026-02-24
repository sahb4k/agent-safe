import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Audit from './pages/Audit'
import Actions from './pages/Actions'
import ActionDetail from './pages/ActionDetail'
import Policies from './pages/Policies'
import Activity from './pages/Activity'

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/actions" element={<Actions />} />
        <Route path="/actions/:name" element={<ActionDetail />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/activity" element={<Activity />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}
