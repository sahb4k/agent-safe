import { useState, type FormEvent } from 'react'
import { useAuth } from './AuthContext'

export default function LoginPage() {
  const { login, startSSOLogin, ssoEnabled, passwordAuthEnabled } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password)
    } catch (err: any) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const handleSSO = async () => {
    setError('')
    setLoading(true)
    try {
      await startSSOLogin()
    } catch (err: any) {
      setError(err.message || 'SSO login failed')
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="w-full max-w-sm">
        <div className="bg-white shadow-lg rounded-lg p-8">
          <div className="text-center mb-6">
            <h1 className="text-2xl font-bold text-gray-900">Agent-Safe</h1>
            <p className="text-sm text-gray-500 mt-1">Governance Dashboard</p>
          </div>

          {error && (
            <div className="bg-red-50 text-red-700 text-sm rounded px-3 py-2 mb-4">
              {error}
            </div>
          )}

          {ssoEnabled && (
            <>
              <button
                onClick={handleSSO}
                disabled={loading}
                className="w-full py-2 px-4 bg-gray-800 text-white rounded-md font-medium hover:bg-gray-900 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Sign in with SSO
              </button>

              {passwordAuthEnabled && (
                <div className="relative my-5">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300" />
                  </div>
                  <div className="relative flex justify-center text-xs">
                    <span className="bg-white px-2 text-gray-500">or</span>
                  </div>
                </div>
              )}
            </>
          )}

          {passwordAuthEnabled && (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                  Username
                </label>
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                  required
                  autoFocus
                />
              </div>

              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2 px-4 bg-blue-600 text-white rounded-md font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? 'Signing in...' : 'Sign in'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  )
}
