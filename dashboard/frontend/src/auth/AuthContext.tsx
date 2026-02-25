import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'

interface User {
  user_id: string
  username: string
  display_name: string
  role: string
}

interface AuthState {
  user: User | null
  token: string | null
  tier: string
  isLoading: boolean
  ssoEnabled: boolean
  passwordAuthEnabled: boolean
  login: (username: string, password: string) => Promise<void>
  loginWithToken: (token: string, user: User) => void
  startSSOLogin: () => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthState | null>(null)

const TOKEN_KEY = 'agent-safe-token'
const USER_KEY = 'agent-safe-user'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    const stored = localStorage.getItem(USER_KEY)
    return stored ? JSON.parse(stored) : null
  })
  const [token, setToken] = useState<string | null>(
    () => localStorage.getItem(TOKEN_KEY)
  )
  const [tier, setTier] = useState('free')
  const [ssoEnabled, setSsoEnabled] = useState(false)
  const [passwordAuthEnabled, setPasswordAuthEnabled] = useState(true)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    // Fetch tier info on mount
    fetch('/api/auth/tier')
      .then(r => r.ok ? r.json() : { tier: 'free', sso_enabled: false, password_auth_enabled: true })
      .then(data => {
        setTier(data.tier)
        setSsoEnabled(data.sso_enabled ?? false)
        setPasswordAuthEnabled(data.password_auth_enabled ?? true)
      })
      .catch(() => setTier('free'))
      .finally(() => setIsLoading(false))
  }, [])

  const login = async (username: string, password: string) => {
    const resp = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: 'Login failed' }))
      throw new Error(err.detail || 'Login failed')
    }
    const data = await resp.json()
    setToken(data.token)
    setUser(data.user)
    localStorage.setItem(TOKEN_KEY, data.token)
    localStorage.setItem(USER_KEY, JSON.stringify(data.user))
  }

  const loginWithToken = (newToken: string, newUser: User) => {
    setToken(newToken)
    setUser(newUser)
    localStorage.setItem(TOKEN_KEY, newToken)
    localStorage.setItem(USER_KEY, JSON.stringify(newUser))
  }

  const startSSOLogin = async () => {
    const resp = await fetch('/api/auth/sso/authorize?redirect_to=/')
    if (!resp.ok) throw new Error('Failed to start SSO login')
    const data = await resp.json()
    window.location.href = data.authorize_url
  }

  const logout = () => {
    setToken(null)
    setUser(null)
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
  }

  return (
    <AuthContext.Provider value={{
      user, token, tier, isLoading,
      ssoEnabled, passwordAuthEnabled,
      login, loginWithToken, startSSOLogin, logout,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
