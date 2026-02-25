import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import LoginPage from './auth/LoginPage'
import SSOCallbackPage from './auth/SSOCallbackPage'
import ProtectedRoute from './auth/ProtectedRoute'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Audit from './pages/Audit'
import Actions from './pages/Actions'
import ActionDetail from './pages/ActionDetail'
import Policies from './pages/Policies'
import Activity from './pages/Activity'
import Clusters from './pages/Clusters'
import Reports from './pages/Reports'
import Users from './pages/Users'
import Alerts from './pages/Alerts'

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/auth/sso/callback" element={<SSOCallbackPage />} />
        <Route path="*" element={
          <ProtectedRoute>
            <Layout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/audit" element={<Audit />} />
                <Route path="/actions" element={<Actions />} />
                <Route path="/actions/:name" element={<ActionDetail />} />
                <Route path="/policies" element={<Policies />} />
                <Route path="/activity" element={<Activity />} />
                <Route path="/clusters" element={<Clusters />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/users" element={<Users />} />
                <Route path="/alerts" element={<Alerts />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Layout>
          </ProtectedRoute>
        } />
      </Routes>
    </AuthProvider>
  )
}
