import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from './AuthContext'

export default function SSOCallbackPage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const { loginWithToken } = useAuth()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const code = searchParams.get('code')
    const state = searchParams.get('state')

    if (!code || !state) {
      setError('Missing authorization code or state parameter')
      return
    }

    const exchange = async () => {
      try {
        const resp = await fetch(
          `/api/auth/sso/token?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
          { method: 'POST' },
        )
        if (!resp.ok) {
          const data = await resp.json().catch(() => ({ detail: 'SSO login failed' }))
          throw new Error(data.detail || 'SSO login failed')
        }
        const data = await resp.json()
        loginWithToken(data.token, data.user)
        navigate('/', { replace: true })
      } catch (err: any) {
        setError(err.message || 'SSO login failed')
      }
    }

    exchange()
  }, [searchParams, loginWithToken, navigate])

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="bg-white shadow-lg rounded-lg p-8 max-w-sm w-full text-center">
          <h2 className="text-lg font-bold text-red-700 mb-2">SSO Login Failed</h2>
          <p className="text-sm text-gray-600 mb-4">{error}</p>
          <a href="/login" className="text-sm text-blue-600 hover:text-blue-800">
            Back to login
          </a>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="text-center">
        <p className="text-sm text-gray-500">Completing SSO login...</p>
      </div>
    </div>
  )
}
